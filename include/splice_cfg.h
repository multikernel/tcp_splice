/* SPDX-License-Identifier: GPL-2.0 */
/*
 * splice_cfg.h - policy configuration shared between the sock_ops BPF program
 * (bpf/) and the userspace control tool (ctl/).
 *
 * The control tool writes one instance into a single-entry BPF array map; the
 * BPF program reads it on each ESTABLISHED callback to decide whether to call
 * bpf_sock_splice_pair(). The kernel module is not involved - it is pure data
 * plane and knows nothing about this policy.
 */
#ifndef _SPLICE_CFG_H
#define _SPLICE_CFG_H

#define SPLICE_MAX_PORTS 16

struct splice_cfg {
	__u8  enabled;		/* master on/off */
	__u8  loopback_only;	/* only splice loopback (127.0.0.0/8, ::1) flows */
	__u16 n_ports;		/* entries in ports[]; 0 means "any port" */
	__u16 ports[SPLICE_MAX_PORTS];	/* allowlist, host byte order; match on
					 * either endpoint's port */
};

#endif /* _SPLICE_CFG_H */
