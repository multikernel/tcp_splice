// SPDX-License-Identifier: GPL-2.0
/*
 * main.c - module entry and the bpf_tcp_splice_pair kfunc.
 *
 * A sock_ops BPF program calls this from each endpoint's ESTABLISHED callback
 * as a policy decision. The kfunc builds a canonical connection key, registers
 * the socket's channel in a module-global pairing registry, and links it to the
 * peer once the other endpoint registers. No sockmap/sockhash is involved, so no
 * sk_psock is created and nothing but our own proto overrides ever writes
 * sk_prot - which is what makes teardown complete. See splice_state.c /
 * splice_proto.c.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>

#include "tcp_splice.h"

/* Per-direction ring size in KiB (see splice_ring_bytes()). Writable at runtime
 * via /sys/module/tcp_splice/parameters/ring_kbytes (or tcp-splice-ctl
 * --ring-kbytes); a change applies to connections spliced afterwards.
 */
unsigned int tcp_splice_ring_kbytes = SPLICE_RING_DEFAULT_KB;
module_param_named(ring_kbytes, tcp_splice_ring_kbytes, uint, 0644);
MODULE_PARM_DESC(ring_kbytes,
		 "per-direction splice ring size in KiB, rounded up to a power of two, applied to newly spliced connections (default 64)");

/* PASSIVE_ESTABLISHED_CB fires before the accepted child transitions from
 * TCP_SYN_RECV to TCP_ESTABLISHED; accept SYN_RECV here.
 */
static bool splice_state_ok(int state)
{
	return state == TCP_ESTABLISHED || state == TCP_SYN_RECV;
}

static int splice_validate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (sk->sk_protocol != IPPROTO_TCP)
		return -EINVAL;
	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
		return -EINVAL;
	if (!splice_state_ok(sk->sk_state))
		return -EINVAL;
	if (tp->repair || tp->urg_data)
		return -EINVAL;
	return 0;
}

/* Build the direction-independent pairing key from @sk's 4-tuple. The two
 * (addr,port) endpoints are sorted so both peers compute the same key; netns is
 * folded in only for loopback addresses (see struct splice_key).
 */
static int splice_make_key(struct sock *sk, struct splice_key *key)
{
	struct inet_sock *inet = inet_sk(sk);
	u8 a[18] = {}, b[18] = {};	/* 16-byte addr + 2-byte port */
	bool loop;

	memset(key, 0, sizeof(*key));
	key->family = sk->sk_family;

	if (sk->sk_family == AF_INET) {
		memcpy(a, &inet->inet_saddr, 4);
		memcpy(b, &inet->inet_daddr, 4);
		loop = ipv4_is_loopback(inet->inet_saddr) ||
		       ipv4_is_loopback(inet->inet_daddr);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (sk->sk_family == AF_INET6) {
		memcpy(a, &sk->sk_v6_rcv_saddr, 16);
		memcpy(b, &sk->sk_v6_daddr, 16);
		loop = ipv6_addr_loopback(&sk->sk_v6_rcv_saddr) ||
		       ipv6_addr_loopback(&sk->sk_v6_daddr);
#endif
	} else {
		return -EINVAL;
	}
	memcpy(a + 16, &inet->inet_sport, 2);
	memcpy(b + 16, &inet->inet_dport, 2);

	/* sort the two endpoints (addr then port) for a canonical key */
	if (memcmp(a, b, sizeof(a)) <= 0) {
		memcpy(key->addr[0], a, 16); memcpy(&key->port[0], a + 16, 2);
		memcpy(key->addr[1], b, 16); memcpy(&key->port[1], b + 16, 2);
	} else {
		memcpy(key->addr[0], b, 16); memcpy(&key->port[0], b + 16, 2);
		memcpy(key->addr[1], a, 16); memcpy(&key->port[1], a + 16, 2);
	}
	if (loop)
		key->ns = (u64)(unsigned long)sock_net(sk);
	return 0;
}

__bpf_kfunc_start_defs();

/**
 * bpf_tcp_splice_pair - register skops->sk for loopback splice and pair it
 *			  with the other endpoint of the same connection.
 * @skops: sock_ops context; skops->sk is one side of the connection.
 *
 * Call from both endpoints' ESTABLISHED callbacks. Each call registers its own
 * socket in the global pairing registry and installs our proto for that socket
 * (under its lock); the second call links the two channels.
 */
__bpf_kfunc int bpf_tcp_splice_pair(struct bpf_sock_ops_kern *skops)
{
	struct tcp_splice_chan *self_c;
	struct splice_key key;
	struct sock *sk;
	int ret;

	if (!skops || !skops->sk)
		return -EINVAL;
	sk = skops->sk;

	ret = splice_validate(sk);
	if (ret)
		return ret;
	ret = splice_make_key(sk, &key);
	if (ret)
		return ret;

	self_c = chan_get_or_alloc(sk);
	if (!self_c)
		return -ENOMEM;

	chan_register_and_pair(self_c, &key);

	/* Swap our proto in for this socket (we hold its lock in the cb). */
	return splice_install(sk);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(tcp_splice_kfunc_set)
BTF_ID_FLAGS(func, bpf_tcp_splice_pair)
BTF_KFUNCS_END(tcp_splice_kfunc_set)

static const struct btf_kfunc_id_set tcp_splice_kfunc_id_set = {
	.owner = THIS_MODULE,
	.set   = &tcp_splice_kfunc_set,
};

static int __init tcp_splice_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SOCK_OPS,
					&tcp_splice_kfunc_id_set);
	if (ret) {
		pr_err("tcp_splice: kfunc registration failed: %d\n", ret);
		return ret;
	}
	pr_info("tcp_splice: loaded, bpf_tcp_splice_pair registered\n");
	return 0;
}

static void __exit tcp_splice_exit(void)
{
	/* Installed sockets hold a module ref, so unload is blocked while any
	 * pair is live; only drain channels that were never installed.
	 */
	splice_drain_all();
	splice_proto_cleanup();
	pr_info("tcp_splice: unloaded\n");
}

module_init(tcp_splice_init);
module_exit(tcp_splice_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cong Wang <cwang@multikernel.io>");
MODULE_DESCRIPTION("TCP loopback splice");
