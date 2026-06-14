// SPDX-License-Identifier: GPL-2.0
/*
 * splice_ring.c - per-direction SPSC byte ring for tcp_splice.
 *
 * Ported verbatim from the in-tree prototype (net/ipv4/tcp_bpf.c). The ring is
 * a power-of-two byte buffer manipulated through circ_buf.h. Producer and
 * consumer are SPSC (one socket each side), so head/tail are updated with
 * release/acquire stores without a data-path lock; ->lock serialises only lazy
 * alloc and teardown. sendmsg copies the user iov into the ring at head;
 * recvmsg copies out at tail. Every byte crosses by an explicit copy into/out
 * of this private kernel buffer: the ring aliases no user or page-cache page.
 */
#include <linux/circ_buf.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/minmax.h>
#include <linux/log2.h>

#include "tcp_splice.h"

size_t splice_ring_bytes(void)
{
	unsigned int kb = clamp(READ_ONCE(tcp_splice_ring_kbytes),
				SPLICE_RING_MIN_KB, SPLICE_RING_MAX_KB);

	return roundup_pow_of_two((size_t)kb << 10);
}

int splice_ring_alloc(struct tcp_splice_chan *s)
{
	size_t bytes = splice_ring_bytes();
	void *buf;

	if (READ_ONCE(s->ring_buf))
		return 0;

	buf = (void *)__get_free_pages(GFP_ATOMIC | __GFP_NOWARN,
				       get_order(bytes));
	if (!buf)
		return -ENOMEM;

	spin_lock_bh(&s->lock);
	if (s->ring_buf) {
		spin_unlock_bh(&s->lock);
		free_pages((unsigned long)buf, get_order(bytes));
		return 0;
	}
	s->ring_buf    = buf;
	s->ring_size   = bytes;
	s->ring_head   = 0;
	s->ring_tail   = 0;
	s->cached_tail = 0;
	spin_unlock_bh(&s->lock);
	return 0;
}

void splice_ring_free(struct tcp_splice_chan *s)
{
	size_t bytes;
	void *buf;

	spin_lock_bh(&s->lock);
	buf   = s->ring_buf;
	bytes = s->ring_size;
	s->ring_buf    = NULL;
	s->ring_size   = 0;
	s->ring_head   = 0;
	s->ring_tail   = 0;
	s->cached_tail = 0;
	spin_unlock_bh(&s->lock);

	if (buf)
		free_pages((unsigned long)buf, get_order(bytes));
}

size_t splice_ring_write(struct tcp_splice_chan *s, struct iov_iter *from,
			 size_t size)
{
	unsigned long head, tail, mask;
	size_t avail, want, to_end, first, second, done;

	if (!s->ring_buf)
		return 0;

	mask = s->ring_size - 1;
	head = s->ring_head;
	/*
	 * Use the producer's cached_tail, refreshed by splice_ring_space()
	 * earlier in this same send. It is conservative - the real ring_tail
	 * only advances - so the free space computed here never exceeds the
	 * true free space, and we avoid a second cross-CPU ring_tail read.
	 */
	tail = s->cached_tail;
	avail = CIRC_SPACE(head, tail, s->ring_size);
	want = min_t(size_t, size, avail);
	if (!want)
		return 0;

	to_end = s->ring_size - (head & mask);
	first  = min_t(size_t, want, to_end);

	done = copy_from_iter(s->ring_buf + (head & mask), first, from);
	if (done < first) {
		/* Publish data before head advance. */
		smp_store_release(&s->ring_head, head + done);
		return done;
	}
	second = want - first;
	if (second) {
		done = copy_from_iter(s->ring_buf, second, from);
		/* Publish data before head advance. */
		smp_store_release(&s->ring_head, head + first + done);
		return first + done;
	}
	/* Publish data before head advance. */
	smp_store_release(&s->ring_head, head + first);
	return first;
}

size_t splice_ring_space(struct tcp_splice_chan *s)
{
	unsigned long head = s->ring_head;
	size_t space = CIRC_SPACE(head, s->cached_tail, s->ring_size);

	if (space)
		return space;
	/*
	 * Cache exhausted; refresh from the consumer-owned cursor - the only
	 * cross-CPU ring_tail read. Pairs with smp_store_release(&ring_tail).
	 */
	s->cached_tail = smp_load_acquire(&s->ring_tail);
	return CIRC_SPACE(head, s->cached_tail, s->ring_size);
}

size_t splice_ring_read(struct tcp_splice_chan *s, struct iov_iter *to,
			size_t size)
{
	unsigned long head, tail, mask;
	size_t have, want, to_end, first, second, done;

	if (!s->ring_buf)
		return 0;

	mask = s->ring_size - 1;
	tail = s->ring_tail;
	/*
	 * Pairs with smp_store_release(&ring_head) in splice_ring_write():
	 * ensure we read producer's data after observing the head advance.
	 */
	head = smp_load_acquire(&s->ring_head);
	have = CIRC_CNT(head, tail, s->ring_size);
	want = min_t(size_t, size, have);
	if (!want)
		return 0;

	to_end = s->ring_size - (tail & mask);
	first  = min_t(size_t, want, to_end);

	done = copy_to_iter(s->ring_buf + (tail & mask), first, to);
	if (done < first) {
		/* Release: free slots before the producer sees the advance. */
		smp_store_release(&s->ring_tail, tail + done);
		return done;
	}
	second = want - first;
	if (second) {
		done = copy_to_iter(s->ring_buf, second, to);
		/* Release: free slots before the producer sees the advance. */
		smp_store_release(&s->ring_tail, tail + first + done);
		return first + done;
	}
	/* Release: free slots before the producer sees the advance. */
	smp_store_release(&s->ring_tail, tail + first);
	return first;
}

bool splice_ring_has_data(const struct tcp_splice_chan *s)
{
	if (!s->ring_buf)
		return false;
	/*
	 * Acquire ring_head so any data published by the producer is visible
	 * if we go on to read it after this check.
	 */
	return CIRC_CNT(smp_load_acquire(&s->ring_head),
			READ_ONCE(s->ring_tail),
			s->ring_size) > 0;
}
