// SPDX-License-Identifier: GPL-2.0
/*
 * tcp_splice_ctl.c - userspace control tool for tcp_splice.
 *
 * Loads the embedded sock_ops BPF program, pushes the policy config into its
 * map, and attaches it to a cgroup so both endpoints of co-located connections
 * trigger bpf_sock_splice_pair(). The kernel module (tcp_splice.ko) must be
 * loaded first. The attachment is a pinned BPF link, so it survives this tool
 * exiting and is removed on "disable".
 *
 *   tcp-splice-ctl enable  --cgroup PATH [--loopback-only] [--ports a,b,c]
 *   tcp-splice-ctl status
 *   tcp-splice-ctl disable
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "splice.skel.h"
#include "splice_cfg.h"

#define PIN_DIR  "/sys/fs/bpf/tcp_splice"
#define PIN_LINK PIN_DIR "/link"
#define PIN_CFG  PIN_DIR "/cfg"

/* The busy-poll budget is the mainline net.core.busy_read sysctl: it seeds
 * sk_ll_usec on every socket, which the splice receiver's ring busy-poll reads.
 */
#define SYSCTL_BUSY_READ "/proc/sys/net/core/busy_read"

/* Per-direction splice ring size, in KiB. A module parameter (writable), so it
 * applies to connections spliced after it is changed. tcp_splice.ko must be
 * loaded for this to exist.
 */
#define PARAM_RING_KB "/sys/module/tcp_splice/parameters/ring_kbytes"

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_WARN)
		return vfprintf(stderr, fmt, ap);
	return 0;
}

static int write_uint(const char *path, unsigned int v)
{
	FILE *f = fopen(path, "w");

	if (!f)
		return -1;
	fprintf(f, "%u\n", v);
	return fclose(f) ? -1 : 0;
}

static int read_uint(const char *path, unsigned int *v)
{
	FILE *f = fopen(path, "r");
	int n;

	if (!f)
		return -1;
	n = fscanf(f, "%u", v);
	fclose(f);
	return n == 1 ? 0 : -1;
}

static void usage(const char *p)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s enable  --cgroup PATH [--loopback-only] [--ports p1,p2,...]\n"
		"                          [--busy-poll-us N] [--ring-kbytes N]\n"
		"  %s status\n"
		"  %s disable\n", p, p, p);
}

static int parse_ports(char *s, struct splice_cfg *cfg)
{
	char *tok, *save = NULL;

	cfg->n_ports = 0;
	for (tok = strtok_r(s, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		if (cfg->n_ports >= SPLICE_MAX_PORTS) {
			fprintf(stderr, "too many ports (max %d)\n",
				SPLICE_MAX_PORTS);
			return -1;
		}
		cfg->ports[cfg->n_ports++] = (unsigned short)atoi(tok);
	}
	return 0;
}

static int cmd_enable(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "cgroup",        required_argument, 0, 'c' },
		{ "loopback-only", no_argument,       0, 'l' },
		{ "ports",         required_argument, 0, 'p' },
		{ "busy-poll-us",  required_argument, 0, 'b' },
		{ "ring-kbytes",   required_argument, 0, 'r' },
		{ 0 }
	};
	struct splice_cfg cfg = { .enabled = 1 };
	const char *cgroup = NULL;
	struct bpf_link *link = NULL;
	struct splice *skel = NULL;
	long busy_poll = -1;		/* -1 = leave the sysctl as is */
	long ring_kb = -1;		/* -1 = leave the module param as is */
	int cg_fd = -1, ret = 1, c;
	__u32 key = 0;

	optind = 2;	/* skip argv[1] == "enable" */
	while ((c = getopt_long(argc, argv, "c:lp:b:r:", opts, NULL)) != -1) {
		switch (c) {
		case 'c': cgroup = optarg; break;
		case 'l': cfg.loopback_only = 1; break;
		case 'p': if (parse_ports(optarg, &cfg)) return 1; break;
		case 'b': busy_poll = atol(optarg); break;
		case 'r': ring_kb = atol(optarg); break;
		default:  usage(argv[0]); return 1;
		}
	}
	if (!cgroup) {
		fprintf(stderr, "enable: --cgroup is required\n");
		return 1;
	}

	skel = splice__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to load BPF object (is tcp_splice.ko loaded?)\n");
		return 1;
	}

	if (bpf_map_update_elem(bpf_map__fd(skel->maps.splice_cfg_map),
				&key, &cfg, BPF_ANY)) {
		fprintf(stderr, "set config: %s\n", strerror(errno));
		goto out;
	}

	/* Set the busy-poll budget via the mainline sysctl (seeds sk_ll_usec on
	 * sockets created afterwards). System-wide; off (0) by default.
	 */
	if (busy_poll >= 0 && write_uint(SYSCTL_BUSY_READ, (unsigned int)busy_poll)) {
		fprintf(stderr, "set %s: %s\n", SYSCTL_BUSY_READ, strerror(errno));
		goto out;
	}

	/* Set the per-direction ring size (module parameter); applies to
	 * connections spliced afterwards. Requires tcp_splice.ko to be loaded.
	 */
	if (ring_kb >= 0 && write_uint(PARAM_RING_KB, (unsigned int)ring_kb)) {
		fprintf(stderr, "set %s: %s (is tcp_splice.ko loaded?)\n",
			PARAM_RING_KB, strerror(errno));
		goto out;
	}

	cg_fd = open(cgroup, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "open %s: %s\n", cgroup, strerror(errno));
		goto out;
	}

	link = bpf_program__attach_cgroup(skel->progs.tcp_splice_sockops, cg_fd);
	if (!link) {
		fprintf(stderr, "attach to cgroup: %s\n", strerror(errno));
		goto out;
	}

	mkdir(PIN_DIR, 0700);
	if (bpf_link__pin(link, PIN_LINK)) {
		fprintf(stderr, "pin link: %s (already enabled?)\n", strerror(errno));
		goto out;
	}
	if (bpf_map__pin(skel->maps.splice_cfg_map, PIN_CFG)) {
		fprintf(stderr, "pin config: %s\n", strerror(errno));
		bpf_link__unpin(link);
		goto out;
	}

	printf("tcp_splice enabled on %s\n", cgroup);
	ret = 0;
out:
	if (cg_fd >= 0)
		close(cg_fd);
	bpf_link__destroy(link);
	splice__destroy(skel);
	return ret;
}

static int cmd_status(void)
{
	struct splice_cfg cfg;
	unsigned int busy_poll, ring_kb;
	__u32 key = 0;
	int fd, i;

	fd = bpf_obj_get(PIN_CFG);
	if (fd < 0) {
		printf("tcp_splice: disabled\n");
		return 0;
	}
	if (bpf_map_lookup_elem(fd, &key, &cfg)) {
		fprintf(stderr, "read config: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	close(fd);

	printf("tcp_splice: enabled (loopback_only=%u, ports=",
	       cfg.loopback_only);
	if (cfg.n_ports == 0)
		printf("any");
	else
		for (i = 0; i < cfg.n_ports; i++)
			printf("%s%u", i ? "," : "", cfg.ports[i]);
	printf(")\n");

	if (read_uint(SYSCTL_BUSY_READ, &busy_poll) == 0)
		printf("            net.core.busy_read=%u\n", busy_poll);
	if (read_uint(PARAM_RING_KB, &ring_kb) == 0)
		printf("            ring_kbytes=%u\n", ring_kb);
	return 0;
}

static int cmd_disable(void)
{
	struct bpf_link *link = bpf_link__open(PIN_LINK);

	if (!link || libbpf_get_error(link)) {
		printf("tcp_splice: not enabled\n");
		return 0;
	}
	bpf_link__unpin(link);		/* drop bpffs ref */
	bpf_link__destroy(link);	/* close fd -> detach from cgroup */
	unlink(PIN_CFG);		/* drop the config map pin */
	rmdir(PIN_DIR);
	printf("tcp_splice disabled\n");
	return 0;
}

int main(int argc, char **argv)
{
	libbpf_set_print(libbpf_print);

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "enable"))
		return cmd_enable(argc, argv);
	if (!strcmp(argv[1], "status"))
		return cmd_status();
	if (!strcmp(argv[1], "disable"))
		return cmd_disable();

	usage(argv[0]);
	return 1;
}
