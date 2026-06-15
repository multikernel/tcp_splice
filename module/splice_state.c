// SPDX-License-Identifier: GPL-2.0
/*
 * splice_state.c - per-socket channel side table and channel lifecycle.
 *
 * The in-tree design stored channel state in struct sk_psock->splice. A module
 * cannot grow sk_psock, so channels live here in a hash table keyed by the
 * owning struct sock. Each channel owns the ring its *peer* writes into and it
 * reads from, plus a percpu_ref that pins the channel (and its ring) across a
 * cross-socket sender's copy.
 */
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>
#include <linux/percpu-refcount.h>
#include <net/sock.h>

#include "tcp_splice.h"

#define SPLICE_HASH_BITS	10
/* by-sock side table: the data path looks up a channel by its owning sock. */
static DEFINE_HASHTABLE(splice_tbl, SPLICE_HASH_BITS);
/* global pairing registry: both endpoints of a connection hash to the same
 * canonical key here, so the second to arrive finds the first and pairs.
 */
static DEFINE_HASHTABLE(pair_tbl, SPLICE_HASH_BITS);
/* one lock guards both tables and the ->peer links. */
static DEFINE_SPINLOCK(splice_tbl_lock);

static u32 pair_hash(const struct splice_key *key)
{
	return jhash(key, sizeof(*key), 0);
}

static bool splice_key_eq(const struct splice_key *a, const struct splice_key *b)
{
	return !memcmp(a, b, sizeof(*a));	/* keys are memset-zeroed first */
}

struct tcp_splice_chan *chan_lookup(struct sock *sk)
{
	struct tcp_splice_chan *s;

	hash_for_each_possible_rcu(splice_tbl, s, hnode, (unsigned long)sk) {
		if (s->sk == sk)
			return s;
	}
	return NULL;
}

/* percpu_ref release: fires once the initial ref and any in-flight cross-socket
 * writer have dropped. Frees the ring and the channel, releases the sock pin.
 */
static void chan_ref_release(struct percpu_ref *ref)
{
	struct tcp_splice_chan *s = container_of(ref, struct tcp_splice_chan,
						 ring_ref);

	splice_ring_free(s);
	percpu_ref_exit(&s->ring_ref);
	sock_put(s->sk);
	kfree_rcu(s, rcu);
}

/* Allocate a channel for @sk (not yet inserted). May run in BPF/softirq
 * context, so everything is GFP_ATOMIC, matching the in-tree allocator.
 */
static struct tcp_splice_chan *chan_alloc(struct sock *sk)
{
	struct tcp_splice_chan *s;

	s = kzalloc(sizeof(*s), GFP_ATOMIC);
	if (!s)
		return NULL;

	spin_lock_init(&s->lock);
	s->sk = sk;

	if (percpu_ref_init(&s->ring_ref, chan_ref_release, 0, GFP_ATOMIC)) {
		kfree(s);
		return NULL;
	}
	if (splice_ring_alloc(s)) {
		percpu_ref_exit(&s->ring_ref);
		kfree(s);
		return NULL;
	}
	sock_hold(sk);	/* pin the socket for the lifetime of the channel */
	return s;
}

struct tcp_splice_chan *chan_get_or_alloc(struct sock *sk)
{
	struct tcp_splice_chan *s, *new;

	rcu_read_lock();
	s = chan_lookup(sk);
	rcu_read_unlock();
	if (s)
		return s;

	new = chan_alloc(sk);
	if (!new)
		return NULL;

	spin_lock_bh(&splice_tbl_lock);
	s = chan_lookup(sk);
	if (s) {
		spin_unlock_bh(&splice_tbl_lock);
		percpu_ref_kill(&new->ring_ref);	/* lost the race */
		return s;
	}
	hash_add_rcu(splice_tbl, &new->hnode, (unsigned long)sk);
	spin_unlock_bh(&splice_tbl_lock);
	return new;
}

/* Register @self in the global pairing registry under @key and try to pair.
 *
 * Both endpoints of a connection compute the same canonical key. The second to
 * arrive finds the first (same key, not self, not already paired) and links the
 * two channels; the first simply parks itself in the registry to be found.
 * Idempotent: a repeat call on an already-paired or already-parked channel is a
 * no-op.
 */
void chan_register_and_pair(struct tcp_splice_chan *self,
			    const struct splice_key *key)
{
	struct tcp_splice_chan *e, *peer = NULL;
	u32 h = pair_hash(key);

	spin_lock_bh(&splice_tbl_lock);
	if (rcu_access_pointer(self->peer))
		goto out;			/* already paired */

	self->pair_key = *key;
	hash_for_each_possible(pair_tbl, e, pair_node, h) {
		if (e != self && !rcu_access_pointer(e->peer) &&
		    splice_key_eq(&e->pair_key, key)) {
			peer = e;
			break;
		}
	}
	if (peer) {
		rcu_assign_pointer(self->peer, peer);
		rcu_assign_pointer(peer->peer, self);
	} else if (!self->in_pairtbl) {
		hash_add(pair_tbl, &self->pair_node, h);
		self->in_pairtbl = true;
	}
out:
	spin_unlock_bh(&splice_tbl_lock);
}

/* Break the pairing: clear both ->peer links and wake any blocked waiters on
 * either side so they re-check the predicate, see peer == NULL, and exit.
 */
void chan_unpair(struct tcp_splice_chan *chan)
{
	struct tcp_splice_chan *peer;

	spin_lock_bh(&splice_tbl_lock);
	peer = rcu_dereference_protected(chan->peer,
					 lockdep_is_held(&splice_tbl_lock));
	if (peer) {
		/* Mark both ends as torn down (not merely unpaired-at-setup) so the
		 * receive path reports EOF here but waits on a channel that has not
		 * paired yet.
		 */
		WRITE_ONCE(chan->unpaired, true);
		rcu_assign_pointer(chan->peer, NULL);
		if (rcu_dereference_protected(peer->peer,
				lockdep_is_held(&splice_tbl_lock)) == chan) {
			WRITE_ONCE(peer->unpaired, true);
			rcu_assign_pointer(peer->peer, NULL);
		}
	}
	spin_unlock_bh(&splice_tbl_lock);

	splice_wake(chan->sk);
	if (peer)
		splice_wake(peer->sk);
}

/* Remove from the table and drop the initial ring_ref. The release callback
 * frees the ring, the channel, and the sock pin once any in-flight cross-socket
 * sender writing into this channel's ring has dropped its hold.
 */
void chan_destroy(struct tcp_splice_chan *chan)
{
	spin_lock_bh(&splice_tbl_lock);
	hash_del_rcu(&chan->hnode);
	if (chan->in_pairtbl) {
		hash_del(&chan->pair_node);
		chan->in_pairtbl = false;
	}
	spin_unlock_bh(&splice_tbl_lock);
	percpu_ref_kill(&chan->ring_ref);
}

/* Module teardown: a paired/installed socket holds a module reference, so the
 * module cannot be unloaded while channels are installed. This drains any
 * channels that were allocated but never installed (e.g. a pair attempt that
 * failed before splice_install()).
 */
void splice_drain_all(void)
{
	struct tcp_splice_chan *s;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&splice_tbl_lock);
	hash_for_each_safe(splice_tbl, bkt, tmp, s, hnode) {
		hash_del_rcu(&s->hnode);
		if (s->in_pairtbl) {
			hash_del(&s->pair_node);
			s->in_pairtbl = false;
		}
		rcu_assign_pointer(s->peer, NULL);
		percpu_ref_kill(&s->ring_ref);
	}
	spin_unlock_bh(&splice_tbl_lock);
	rcu_barrier();
}
