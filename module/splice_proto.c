// SPDX-License-Identifier: GPL-2.0
/*
 * splice_proto.c - proto-ops interposition for tcp_splice.
 *
 * A module cannot edit the static tcp_bpf_sendmsg/recvmsg, so the data path is
 * interposed by replacing each paired socket's sk_prot with a clone of its
 * current proto (kmemdup, overriding sendmsg/recvmsg/close/sock_is_readable).
 * The overrides look up the channel in the side table and move data through the
 * ring; the saved base proto carries only the pre-pairing startup window and
 * FIN/RST/control. The swap happens per side under that socket's own lock (in
 * the kfunc's sock_ops callback); a sender only writes into the peer's ring once
 * the peer has installed its own proto. Teardown runs from the clone's close
 * handler, and an installed socket holds a module reference so the module cannot
 * be unloaded while a pair is live.
 *
 * Once both ends are paired the ring is the sole data path: there is no per-write
 * TCP fallback, so a full ring blocks the sender (stream flow control) and a ring
 * byte can never overtake TCP data. There is one TCP->ring boundary per stream
 * (ring_seq, the frozen write_seq), so the receiver simply reads startup TCP up
 * to ring_seq and then drains the ring - no per-message bookkeeping.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/sched/signal.h>
#include <linux/poll.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/busy_poll.h>
#include <linux/version.h>

#include "tcp_splice.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
#define SPLICE_RECVMSG_ADDR_LEN 0
#else
#define SPLICE_RECVMSG_ADDR_LEN 1
#endif

/* ---- wakeups ---------------------------------------------------------- */

/* Wake any waiters parked on @sk (teardown: they re-check and see peer==NULL). */
void splice_wake(struct sock *sk)
{
	wait_queue_head_t *wq = sk_sleep(sk);

	smp_mb();
	if (wq && waitqueue_active(wq))
		wake_up_interruptible_all(wq);
}

/* Wake the receiver after a producer ring write. The _poll variant carries
 * EPOLLIN|EPOLLRDNORM so poll()/epoll waiters see it; the smp_mb() orders the
 * ring head publish before the waitqueue_active() check (lost-wakeup pairing).
 */
static void splice_wake_sync(struct sock *sk)
{
	wait_queue_head_t *wq = sk_sleep(sk);

	smp_mb();
	if (wq && waitqueue_active(wq))
		wake_up_interruptible_sync_poll(wq, EPOLLIN | EPOLLRDNORM);
}

/* Wake a sender parked on a full ring after the receiver frees space (hard
 * backpressure). EPOLLOUT for poll()/epoll waiters; smp_mb() orders the
 * ring_tail publish (in splice_ring_read) before the waitqueue_active() check.
 */
static void splice_wake_send(struct sock *sk)
{
	wait_queue_head_t *wq = sk_sleep(sk);

	smp_mb();
	if (wq && waitqueue_active(wq))
		wake_up_interruptible_sync_poll(wq, EPOLLOUT | EPOLLWRNORM);
}

/* ---- receive path ----------------------------------------------------- */

/* True once ring data is next in stream order for this receiver: the peer
 * (sender) has switched to the ring and our copied_seq has reached the peer's
 * ring_seq, so the startup TCP that precedes the ring is fully consumed. Reads
 * ring data first (acquire) so the peer's ring_active/ring_seq - published
 * before the ring payload - are visible.
 */
static bool splice_ring_ready(struct sock *sk, struct tcp_splice_chan *s)
{
	struct tcp_splice_chan *peer;
	bool ready = false;

	rcu_read_lock();
	peer = rcu_dereference(s->peer);
	if (peer && splice_ring_has_data(s) && READ_ONCE(peer->ring_active) &&
	    !before(READ_ONCE(tcp_sk(sk)->copied_seq), READ_ONCE(peer->ring_seq)))
		ready = true;
	rcu_read_unlock();
	return ready;
}

/* Something can be handed to userspace right now: queued (startup) TCP bytes, or
 * ring data once past the startup boundary. Ring data still gated on unconsumed
 * startup TCP is deliberately NOT counted - that TCP must be read first, and
 * counting the ring here would busy-spin waiting for it.
 */
static bool splice_recv_deliverable(struct sock *sk, struct tcp_splice_chan *s)
{
	return !skb_queue_empty(&sk->sk_receive_queue) ||
	       splice_ring_ready(sk, s);
}

static bool splice_recv_ready(struct sock *sk, struct tcp_splice_chan *s)
{
	return splice_recv_deliverable(sk, s) ||
	       READ_ONCE(sk->sk_err) ||
	       (READ_ONCE(sk->sk_shutdown) & RCV_SHUTDOWN) ||
	       READ_ONCE(s->unpaired);	/* torn-down pair; a not-yet-paired
					 * (parked) channel keeps waiting */
}

static long splice_recv_wait(struct sock *sk, struct tcp_splice_chan *s,
			     long timeo)
{
	return wait_event_interruptible_timeout(*sk_sleep(sk),
						splice_recv_ready(sk, s), timeo);
}

/* Bounded busy-poll on the ring before parking the receiver. The budget comes
 * from the socket's SO_BUSY_POLL value (sk_ll_usec), which the mainline
 * net.core.busy_read sysctl initializes on every socket; sk_can_busy_loop() and
 * sk_busy_loop_timeout() read it. A budget of 0 (default) makes this a no-op.
 *
 * Unlike sk_busy_loop()/napi_busy_loop(), this spins on the in-kernel ring
 * directly rather than polling a NAPI instance, so it is effective on loopback
 * and veth - which deliver via the per-CPU backlog and expose no pollable
 * napi_id (the generic busy-poll is a no-op there). We only borrow the budget
 * value, not the NAPI machinery.
 */
static void splice_busy_loop(struct sock *sk, struct tcp_splice_chan *s)
{
	unsigned long start;

	if (!sk_can_busy_loop(sk))
		return;

	start = busy_loop_current_time();
	do {
		cpu_relax();
		if (splice_recv_ready(sk, s) || signal_pending(current))
			return;
	} while (!sk_busy_loop_timeout(sk, start));
}

/* Read from the saved base proto, papering over the 7.1 recvmsg signature. */
static int splice_base_recvmsg(struct tcp_splice_chan *chan, struct sock *sk,
			       struct msghdr *msg, size_t len, int flags,
			       int *addr_len)
{
#if SPLICE_RECVMSG_ADDR_LEN
	return chan->base_prot->recvmsg(sk, msg, len, flags, addr_len);
#else
	(void)addr_len;
	return chan->base_prot->recvmsg(sk, msg, len, flags);
#endif
}

/*
 * Ordered merge of the two receive paths. Hard backpressure means there is one
 * boundary: startup TCP (all seq < the peer's ring_seq) precedes ring data, and
 * once spliced no TCP follows. So we deliver in stream order with no per-chunk
 * bookkeeping:
 *
 *   - read queued (startup) TCP first - it is all below ring_seq, hence ahead
 *     of any ring byte, so reading it uncapped never reorders;
 *   - once copied_seq has reached the peer's ring_seq (startup drained) and the
 *     TCP queue is empty, drain the ring directly (ring reads don't advance
 *     copied_seq);
 *   - at EOF, flush remaining ring data even if copied_seq has not reached
 *     ring_seq (a reset means the missing startup TCP will never arrive).
 *
 * copied_seq is this socket's, read locklessly: only this reader advances it.
 * Called without the socket lock (may sleep); returns bytes copied or -errno.
 */
static int splice_recvmsg_merge(struct sock *sk, struct tcp_splice_chan *s,
				struct msghdr *msg, size_t len, int flags,
				int *addr_len)
{
	long timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	size_t total = 0;
	int err = 0;

	/* The ring cannot serve a peek without consuming; defer the (rare) peek
	 * to TCP, as the pre-merge code did.
	 */
	if (flags & MSG_PEEK)
		return splice_base_recvmsg(s, sk, msg, len, flags, addr_len);

	while (total < len) {
		struct tcp_splice_chan *peer;
		bool ring_ready, eof;
		int n;

		eof = (READ_ONCE(sk->sk_shutdown) & RCV_SHUTDOWN) ||
		      READ_ONCE(sk->sk_err);

		/* Ring is next once past the startup boundary (or, at EOF, flush
		 * whatever is there). splice_ring_has_data() acquires ring_head, so
		 * the peer's ring_active/ring_seq are visible.
		 */
		rcu_read_lock();
		peer = rcu_dereference(s->peer);
		if (peer)
			ring_ready = splice_ring_has_data(s) &&
				     READ_ONCE(peer->ring_active) &&
				     (eof || !before(READ_ONCE(tcp_sk(sk)->copied_seq),
						     READ_ONCE(peer->ring_seq)));
		else
			/* peer == NULL: either torn down (->unpaired) or not paired
			 * yet (parked). A torn-down peer may have written a final
			 * message into our own ring and then closed; that data is
			 * still valid, so drain it before reporting EOF (no further
			 * startup TCP will arrive, so the ring_seq gate no longer
			 * applies). A parked channel has no ring data and just waits.
			 */
			ring_ready = READ_ONCE(s->unpaired) &&
				     splice_ring_has_data(s);
		rcu_read_unlock();

		if (ring_ready && skb_queue_empty(&sk->sk_receive_queue)) {
			n = splice_ring_read(s, &msg->msg_iter, len - total);
			if (n > 0) {
				total += n;
				/* freed ring space: wake a backpressured sender */
				rcu_read_lock();
				peer = rcu_dereference(s->peer);
				if (peer)
					splice_wake_send(peer->sk);
				rcu_read_unlock();
				continue;
			}
		}

		/* Startup TCP precedes the ring; it is all below ring_seq, so read
		 * whatever is queued, uncapped, in order.
		 */
		if (!skb_queue_empty(&sk->sk_receive_queue)) {
			n = splice_base_recvmsg(s, sk, msg, len - total,
						flags | MSG_DONTWAIT, addr_len);
			if (n > 0) {
				total += n;
				continue;
			}
			if (n < 0 && n != -EAGAIN) {
				if (total)
					break;
				return n;
			}
		}

		/* Nothing delivered this round. Re-decide against fresh state so a
		 * FIN that landed mid-iteration cannot make us report EOF while ring
		 * data - or its now-arrived startup TCP - is still pending (which
		 * would truncate the stream).
		 */
		if (total)
			break;
		if (READ_ONCE(sk->sk_err)) {
			err = -sk->sk_err;
			break;
		}
		if (READ_ONCE(s->unpaired) && !splice_ring_has_data(s))
			break;
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
		if (splice_recv_deliverable(sk, s) ||
		    ((READ_ONCE(sk->sk_shutdown) & RCV_SHUTDOWN) &&
		     splice_ring_has_data(s)))	/* EOF: flush remaining ring */
			continue;
		if (READ_ONCE(sk->sk_shutdown) & RCV_SHUTDOWN)
			break;			/* EOF, both paths drained */
		if (!timeo) {
			err = -EAGAIN;
			break;
		}
		splice_busy_loop(sk, s);
		if (splice_recv_deliverable(sk, s))
			continue;
		timeo = splice_recv_wait(sk, s, timeo);
	}

	return total ? (int)total : err;
}

/* ---- send path -------------------------------------------------------- */

/* The sender can make progress, or must stop: the peer's ring has room, the
 * pair is gone, or the socket errored / was shut down for send.
 */
static bool splice_send_ready(struct sock *sk, struct tcp_splice_chan *self_s)
{
	struct tcp_splice_chan *p;
	bool ready;

	rcu_read_lock();
	p = rcu_dereference(self_s->peer);
	ready = !p ||
		READ_ONCE(sk->sk_err) ||
		(READ_ONCE(sk->sk_shutdown) & SEND_SHUTDOWN) ||
		(READ_ONCE(p->installed) && READ_ONCE(p->ring_buf) &&
		 splice_ring_space(p) > 0);
	rcu_read_unlock();
	return ready;
}

static long splice_send_wait(struct sock *sk, struct tcp_splice_chan *self_s,
			     long timeo)
{
	return wait_event_interruptible_timeout(*sk_sleep(sk),
						splice_send_ready(sk, self_s),
						timeo);
}

/*
 * Push the whole message through the peer's ring. Once a socket is spliced it
 * never falls back to TCP (that is what makes the bypass rate stable and keeps a
 * ring byte from ever overtaking TCP), so a full ring blocks the sender until
 * the receiver drains it - ordinary stream flow control, like a full sndbuf.
 * Returns bytes sent, or a negative errno if nothing could be sent.
 */
static int splice_send_ring(struct sock *sk, struct tcp_splice_chan *self_s,
			    struct msghdr *msg, size_t size)
{
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	size_t total = 0;

	while (size > 0) {
		struct tcp_splice_chan *peer_s = NULL;
		size_t done, space = 0;
		int xerr = 0;

		/* Peer / peer->sk accesses are under RCU. With ring space, grab
		 * the peer ring_ref before dropping RCU: that pins peer_s (and its
		 * ring) so the copy can run outside RCU and fault/sleep. peer->sk
		 * is not pinned by the ref, so do not touch it after unlock.
		 */
		rcu_read_lock();
		{
			struct tcp_splice_chan *p =
				rcu_dereference(self_s->peer);

			if (!p)
				xerr = -EPIPE;		/* pair gone */
			else if (READ_ONCE(sk->sk_err))
				xerr = -READ_ONCE(sk->sk_err);
			else if (READ_ONCE(sk->sk_shutdown) & SEND_SHUTDOWN)
				xerr = -EPIPE;
			else if (READ_ONCE(p->installed) &&
				 READ_ONCE(p->ring_buf)) {
				space = splice_ring_space(p);
				if (space &&
				    percpu_ref_tryget_live(&p->ring_ref))
					peer_s = p;
			}
		}
		rcu_read_unlock();

		if (xerr)
			return total ? total : xerr;

		if (peer_s) {
			done = splice_ring_write(peer_s, &msg->msg_iter,
						 min(size, space));
			percpu_ref_put(&peer_s->ring_ref);
			if (done) {
				struct tcp_splice_chan *p;

				total += done;
				size  -= done;
				rcu_read_lock();
				p = rcu_dereference(self_s->peer);
				if (p)
					splice_wake_sync(p->sk);
				rcu_read_unlock();
				continue;
			}
		}

		/* Ring full: block for space. */
		if (!timeo)
			return total ? total : -EAGAIN;
		if (signal_pending(current))
			return total ? total : sock_intr_errno(timeo);
		timeo = splice_send_wait(sk, self_s, timeo);
		if (timeo < 0)
			return total ? total : sock_intr_errno(timeo);
	}
	return total;
}

/* ---- proto overrides -------------------------------------------------- */

static int splice_prot_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tcp_splice_chan *chan;
	bool peer_ready;

	rcu_read_lock();
	chan = chan_lookup(sk);
	rcu_read_unlock();
	if (WARN_ON_ONCE(!chan))
		return -EPIPE;

	/* Urgent / out-of-band data is not part of the in-order byte stream; let
	 * TCP carry it (the receiver pulls it out via the urgent pointer).
	 */
	if (msg->msg_flags & MSG_OOB)
		return chan->base_prot->sendmsg(sk, msg, size);

	rcu_read_lock();
	{
		struct tcp_splice_chan *p = rcu_dereference(chan->peer);

		peer_ready = p && READ_ONCE(p->installed) &&
			     READ_ONCE(p->ring_buf);
	}
	rcu_read_unlock();

	/* Startup window: until the peer has installed its proto, carry data over
	 * TCP - the receiver's merge orders it ahead of ring data by ring_seq.
	 * Once spliced, everything goes through the ring (blocking when full).
	 */
	if (!peer_ready)
		return chan->base_prot->sendmsg(sk, msg, size);

	/* First ring write: freeze the handoff boundary at the current write_seq.
	 * Every byte so far went via TCP; nothing goes via TCP from here, so it
	 * stays frozen. Published (smp_wmb, then before the ring payload's release)
	 * so the receiver observes a consistent ring_seq/ring_active.
	 */
	if (!READ_ONCE(chan->ring_active)) {
		chan->ring_seq = READ_ONCE(tcp_sk(sk)->write_seq);
		smp_wmb();
		WRITE_ONCE(chan->ring_active, true);
	}

	return splice_send_ring(sk, chan, msg, size);
}

#if SPLICE_RECVMSG_ADDR_LEN
static int splice_prot_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			       int flags, int *addr_len)
#else
static int splice_prot_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			       int flags)
#endif
{
	struct tcp_splice_chan *chan;

	rcu_read_lock();
	chan = chan_lookup(sk);
	rcu_read_unlock();
	if (WARN_ON_ONCE(!chan))
		return -EPIPE;

#if SPLICE_RECVMSG_ADDR_LEN
	return splice_recvmsg_merge(sk, chan, msg, len, flags, addr_len);
#else
	return splice_recvmsg_merge(sk, chan, msg, len, flags, NULL);
#endif
}

static bool splice_prot_is_readable(struct sock *sk)
{
	struct tcp_splice_chan *chan;
	struct proto *base = NULL;
	bool ring = false;

	rcu_read_lock();
	chan = chan_lookup(sk);
	if (chan) {
		base = chan->base_prot;
		/* Ring data counts as readable only once it is next in stream
		 * order (past the startup-TCP boundary). Before that, TCP
		 * readability (below) signals when the startup TCP lands.
		 */
		ring = splice_ring_ready(sk, chan);
	}
	rcu_read_unlock();

	if (ring)
		return true;
	if (base && base->sock_is_readable)
		return base->sock_is_readable(sk);
	return false;
}

/*
 * Idempotent teardown, callable from close/disconnect/unhash. Atomically claims
 * the teardown via xchg(installed); the winner unpairs, restores the base proto,
 * destroys the channel and drops the module ref. Runs entirely under RCU so the
 * channel can't be freed mid-teardown. Returns the base proto to chain to
 * (stable once set), or NULL if @sk has no channel.
 *
 * Restoring sk_prot to @base *before* the caller chains to base->op means any
 * internal unhash (sk->sk_prot->unhash) dispatches through base, not our clone,
 * so the overrides below never re-enter this path.
 */
static struct proto *splice_teardown(struct sock *sk)
{
	struct tcp_splice_chan *chan;
	struct proto *base = NULL;

	rcu_read_lock();
	chan = chan_lookup(sk);
	if (chan) {
		base = READ_ONCE(chan->base_prot);
		if (xchg(&chan->installed, 0)) {	/* claim the teardown */
			chan_unpair(chan);		/* break pair, wake both */
			sock_replace_proto(sk, base);	/* restore real proto */
			chan_destroy(chan);		/* kill ref -> async free */
			module_put(THIS_MODULE);
		}
	}
	rcu_read_unlock();
	return base;
}

static void splice_prot_close(struct sock *sk, long timeout)
{
	struct proto *base = splice_teardown(sk);

	(base ? base : READ_ONCE(sk->sk_prot))->close(sk, timeout);
}

static int splice_prot_disconnect(struct sock *sk, int flags)
{
	struct proto *base = splice_teardown(sk);

	return (base ? base : READ_ONCE(sk->sk_prot))->disconnect(sk, flags);
}

static void splice_prot_unhash(struct sock *sk)
{
	struct proto *base = splice_teardown(sk);
	struct proto *p = base ? base : READ_ONCE(sk->sk_prot);

	if (p->unhash)
		p->unhash(sk);
}

/* Some sockets are freed without ever going through close/disconnect/unhash -
 * notably a passively-spliced child (we install at TCP_SYN_RECV) that is aborted
 * or never accepted, which the stack tears down via ->destroy
 * (inet_csk_destroy_sock). Without hooking ->destroy that path skips
 * splice_teardown(), leaking the channel and the module reference taken in
 * splice_install(). teardown is idempotent (xchg), so this is just one more entry
 * point; for a normally-closed socket sk_prot is already restored to base by the
 * time ->destroy runs, so this override is not even reached.
 */
static void splice_prot_destroy(struct sock *sk)
{
	struct proto *base = splice_teardown(sk);
	struct proto *p = base ? base : READ_ONCE(sk->sk_prot);

	if (p->destroy)
		p->destroy(sk);
}

/* ---- proto clone registry + install ----------------------------------- */

struct splice_clone {
	struct proto		*base;
	struct proto		*clone;
	struct list_head	node;
};

static LIST_HEAD(clone_list);
static DEFINE_SPINLOCK(clone_lock);

static struct proto *clone_lookup(struct proto *base)
{
	struct splice_clone *c;

	list_for_each_entry(c, &clone_list, node)
		if (c->base == base)
			return c->clone;
	return NULL;
}

/* Get (or lazily build) the module proto cloned from @base. Cached per base,
 * so there are only a handful (one per tcp_bpf variant the sockets use).
 */
static struct proto *clone_get(struct proto *base)
{
	struct splice_clone *new;
	struct proto *clone;

	spin_lock_bh(&clone_lock);
	clone = clone_lookup(base);
	spin_unlock_bh(&clone_lock);
	if (clone)
		return clone;

	new = kzalloc(sizeof(*new), GFP_ATOMIC);
	if (!new)
		return NULL;
	clone = kmemdup(base, sizeof(*clone), GFP_ATOMIC);
	if (!clone) {
		kfree(new);
		return NULL;
	}
	clone->sendmsg		= splice_prot_sendmsg;
	clone->recvmsg		= splice_prot_recvmsg;
	clone->close		= splice_prot_close;
	clone->disconnect	= splice_prot_disconnect;
	clone->unhash		= splice_prot_unhash;
	clone->destroy		= splice_prot_destroy;
	clone->sock_is_readable	= splice_prot_is_readable;
	new->base  = base;
	new->clone = clone;

	spin_lock_bh(&clone_lock);
	if (clone_lookup(base)) {		/* lost the race */
		struct proto *existing = clone_lookup(base);

		spin_unlock_bh(&clone_lock);
		kfree(clone);
		kfree(new);
		return existing;
	}
	list_add(&new->node, &clone_list);
	spin_unlock_bh(&clone_lock);
	return clone;
}

/* Swap our proto in for @sk. Caller (the kfunc) holds @sk's lock. */
int splice_install(struct sock *sk)
{
	struct tcp_splice_chan *chan;
	struct proto *base, *clone;

	rcu_read_lock();
	chan = chan_lookup(sk);
	rcu_read_unlock();
	if (!chan)
		return -ENOENT;
	if (READ_ONCE(chan->installed))
		return 0;

	base = sk->sk_prot;
	clone = clone_get(base);
	if (!clone)
		return -ENOMEM;
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	chan->base_prot = base;
	smp_wmb();			/* base_prot visible before installed */
	WRITE_ONCE(chan->installed, 1);
	sock_replace_proto(sk, clone);
	return 0;
}

/* Free the cloned protos at module exit. Safe because an installed socket holds
 * a module reference, so unload is blocked until every clone is unused.
 */
void splice_proto_cleanup(void)
{
	struct splice_clone *c, *tmp;

	spin_lock_bh(&clone_lock);
	list_for_each_entry_safe(c, tmp, &clone_list, node) {
		list_del(&c->node);
		kfree(c->clone);
		kfree(c);
	}
	spin_unlock_bh(&clone_lock);
}
