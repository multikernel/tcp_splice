# Build the userspace control tool: host cc + libbpf -> tcp-splice-ctl
# Requires: libbpf-dev (headers + lib). Depends on the BPF skeleton produced
# by ../bpf (make -C ../bpf skel).
CC       ?= cc
BPFDIR   := ../bpf
INCLUDES := -I$(BPFDIR) -I../include
CFLAGS   ?= -O2 -Wall
LDLIBS   := -lbpf

all: tcp-splice-ctl

# Skeleton is generated in ../bpf; ensure it exists before we compile.
$(BPFDIR)/splice.skel.h:
	$(MAKE) -C $(BPFDIR) skel

tcp-splice-ctl: tcp_splice_ctl.c $(BPFDIR)/splice.skel.h ../include/splice_cfg.h
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@ $(LDLIBS)

clean:
	rm -f tcp-splice-ctl

.PHONY: all clean
