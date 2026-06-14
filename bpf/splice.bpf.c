// SPDX-License-Identifier: GPL-2.0
/*
 * splice.bpf.c - sock_ops policy program for tcp_splice.
 *
 * On each endpoint's ESTABLISHED callback, consults the shared policy config
 * (written by tcp-splice-ctl) and, if the flow qualifies, calls the module's
 * bpf_tcp_splice_pair() kfunc. The kfunc registers this socket and pairs it
 * with the other endpoint (see the module's splice_state.c).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "splice_cfg.h"

#ifndef AF_INET
#define AF_INET		2
#define AF_INET6	10
#endif

/* Provided by the tcp_splice.ko module. */
extern int bpf_tcp_splice_pair(struct bpf_sock_ops_kern *skops) __ksym;
/* Core kfunc: turn the UAPI ctx into the kernel ctx the kfunc expects. */
extern void *bpf_cast_to_kern_ctx(void *obj) __ksym;

/* Single-entry config map written by tcp-splice-ctl. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct splice_cfg);
} splice_cfg_map SEC(".maps");

static __always_inline int is_loopback(struct bpf_sock_ops *ctx)
{
	if (ctx->family == AF_INET)
		return (bpf_ntohl(ctx->local_ip4) >> 24) == 127;
	/* AF_INET6: ::1 */
	return ctx->local_ip6[0] == 0 && ctx->local_ip6[1] == 0 &&
	       ctx->local_ip6[2] == 0 && ctx->local_ip6[3] == bpf_htonl(1);
}

static __always_inline int port_allowed(struct bpf_sock_ops *ctx,
					struct splice_cfg *cfg)
{
	__u16 lport = ctx->local_port;			/* host byte order */
	__u16 rport = bpf_ntohl(ctx->remote_port);	/* net -> host */
	int i;

	if (cfg->n_ports == 0)
		return 1;				/* any port */
	for (i = 0; i < SPLICE_MAX_PORTS; i++) {
		if (i >= cfg->n_ports)
			break;
		if (cfg->ports[i] == lport || cfg->ports[i] == rport)
			return 1;
	}
	return 0;
}

static __always_inline int flow_allowed(struct bpf_sock_ops *ctx)
{
	struct splice_cfg *cfg;
	__u32 key = 0;

	cfg = bpf_map_lookup_elem(&splice_cfg_map, &key);
	if (!cfg || !cfg->enabled)
		return 0;
	if (ctx->family != AF_INET && ctx->family != AF_INET6)
		return 0;
	if (cfg->loopback_only && !is_loopback(ctx))
		return 0;
	return port_allowed(ctx, cfg);
}

SEC("sockops")
int tcp_splice_sockops(struct bpf_sock_ops *ctx)
{
	if (ctx->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
	    ctx->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
		return 0;

	if (!flow_allowed(ctx))
		return 0;

	/* Pair this endpoint; the other end's callback pairs itself. The kfunc
	 * takes the kernel ctx (struct bpf_sock_ops_kern *).
	 */
	bpf_tcp_splice_pair(bpf_cast_to_kern_ctx(ctx));
	return 0;
}

char _license[] SEC("license") = "GPL";
