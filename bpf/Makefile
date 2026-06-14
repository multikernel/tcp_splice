# Build the sock_ops BPF program: clang -target bpf -> splice.bpf.o
# Requires: clang, bpftool, libbpf headers (libbpf-dev), and CONFIG_DEBUG_INFO_BTF
# on the running kernel (for vmlinux.h generation).
CLANG    ?= clang
BPFTOOL  ?= bpftool
ARCH     := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

INCLUDES := -I. -I../include
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

all: splice.bpf.o

# vmlinux.h is generated from the running kernel's BTF; never committed.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

splice.bpf.o: splice.bpf.c vmlinux.h ../include/splice_cfg.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Skeleton consumed by the control tool (ctl/). Fixed name -> struct splice,
# splice__open()/load()/destroy(), skel->progs/maps.
splice.skel.h: splice.bpf.o
	$(BPFTOOL) gen skeleton $< name splice > $@

skel: splice.skel.h

clean:
	rm -f splice.bpf.o splice.skel.h vmlinux.h

.PHONY: all skel clean
