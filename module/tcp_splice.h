/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tcp_splice - TCP loopback splice, out-of-tree module form.
 *
 * The in-tree prototype (bpf_sock_splice_pair) stored its per-socket state in
 * a new struct sk_psock->splice field and hooked teardown from net/core/skmsg.c.
 * A loadable module on a stock kernel can do neither, so:
 *
 *   - per-socket channel state lives in a module-private hash table keyed by
 *     the owning struct sock (splice_state.* / tcp_splice_main.c), and
 *   - the data path and teardown are interposed by replacing the socket's
 *     proto ops (added in a later step), not by editing core files.
 *
 * The byte ring itself (splice_ring.c) is unchanged from the in-tree design:
 * a per-direction SPSC circular buffer, lockless on the data path.
 */
#ifndef _TCP_SPLICE_H
#define _TCP_SPLICE_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/percpu-refcount.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>
#include <linux/list.h>

struct sock;
struct iov_iter;

/*
 * Per-direction byte ring size, set via the ring_kbytes module parameter (in
 * KiB), rounded up to a power of two and clamped to [MIN, MAX] at allocation.
 * The ring is the sole data path once spliced, so the size does not change the
 * bypass ratio - it is a flow-control/memory knob: a larger ring lets a fast
 * sender run further ahead before it blocks on a full ring, fewer block/wake
 * round-trips per byte, at the cost of memory (two rings per connection). A
 * change applies only to connections spliced afterwards.
 */
#define SPLICE_RING_DEFAULT_KB	64U
#define SPLICE_RING_MIN_KB	4U
#define SPLICE_RING_MAX_KB	16384U		/* 16 MiB */

extern unsigned int tcp_splice_ring_kbytes;	/* the module parameter */
size_t splice_ring_bytes(void);			/* sanitized size for a new ring */

/*
 * Per-socket splice channel. One channel per paired socket; the channel owns
 * the ring that the *peer* writes into and this socket reads from.
 *
 * Producer and consumer cursors sit on separate cache lines: the writer's
 * release-store of ring_head must not invalidate the reader's hot ring_tail
 * line, and vice versa. cached_tail is the producer's private cache of
 * ring_tail (standard SPSC cursor caching).
 */
struct proto;
struct msghdr;

/*
 * Canonical connection key for the global pairing registry. The two endpoints
 * of one connection produce an identical key: the (addr,port) pair is sorted so
 * the key is direction-independent, and the netns is folded in only for
 * non-routable (loopback) addresses, where the same tuple can legitimately
 * exist in different namespaces. For routable addresses (e.g. container veth
 * IPs) ns stays 0 so the two endpoints in *different* netns still match.
 */
struct splice_key {
	__u16	family;
	__be16	port[2];	/* sorted alongside addr[] */
	__be32	addr[2][4];	/* two endpoints, 16 bytes each (v4 in [x][0]) */
	__u64	ns;		/* netns disambiguator for loopback; 0 if routable */
};

struct tcp_splice_chan {
	struct tcp_splice_chan __rcu	*peer;	/* NULL after unpair */
	struct sock			*sk;	/* owning socket (hash key) */
	struct proto			*base_prot; /* saved sk_prot before swap */
	int				installed;  /* our proto swapped in; also
						     * the teardown claim token */
	/*
	 * The TCP->ring handoff for the stream this socket *sends*. Hard
	 * backpressure means there is exactly one transition: startup data goes
	 * over TCP (bytes with seq < ring_seq), then everything goes through the
	 * ring (logically following ring_seq, since write_seq is frozen). Set
	 * once by the sender; the peer-receiver gates ring delivery on its
	 * copied_seq reaching ring_seq, so the ring never overtakes startup TCP.
	 */
	u32				ring_seq;
	bool				ring_active;
	spinlock_t			lock;	/* alloc / teardown only */
	void				*ring_buf;  /* order-2 pages */
	size_t				ring_size;  /* power of 2 */
	struct percpu_ref		ring_ref;   /* cross-socket writers */

	struct hlist_node		hnode;	/* by-sock side table */
	struct splice_key		pair_key;   /* key in the pairing registry */
	struct hlist_node		pair_node;  /* by-key pairing registry */
	bool				in_pairtbl; /* linked into pairing registry */
	bool				unpaired;   /* peer was set then torn down;
						     * distinguishes a dead pair from
						     * a not-yet-paired (parked) one,
						     * so the latter waits at setup
						     * instead of reporting EOF */
	struct rcu_head			rcu;

	unsigned long	ring_head ____cacheline_aligned_in_smp;
	unsigned long	cached_tail;
	unsigned long	ring_tail ____cacheline_aligned_in_smp;
};

/* splice_ring.c - the per-direction SPSC byte ring (copy-based). */
int    splice_ring_alloc(struct tcp_splice_chan *s);
void   splice_ring_free(struct tcp_splice_chan *s);
size_t splice_ring_write(struct tcp_splice_chan *s, struct iov_iter *from,
			 size_t size);
size_t splice_ring_read(struct tcp_splice_chan *s, struct iov_iter *to,
			size_t size);
size_t splice_ring_space(struct tcp_splice_chan *s);
bool   splice_ring_has_data(const struct tcp_splice_chan *s);

/* splice_state.c - the sock -> channel side table, global pairing registry,
 * and channel lifecycle.
 */
struct tcp_splice_chan *chan_lookup(struct sock *sk);
struct tcp_splice_chan *chan_get_or_alloc(struct sock *sk);
void   chan_register_and_pair(struct tcp_splice_chan *self,
			      const struct splice_key *key);
void   chan_unpair(struct tcp_splice_chan *chan);
void   chan_destroy(struct tcp_splice_chan *chan);
void   splice_drain_all(void);

/* splice_proto.c - proto-ops interposition (data path + teardown). */
int    splice_install(struct sock *sk);	/* swap in our proto; sk must be locked */
void   splice_wake(struct sock *sk);	/* wake parked waiters on @sk */
void   splice_proto_cleanup(void);	/* free cloned protos at module exit */

#endif /* _TCP_SPLICE_H */
