# Out-of-tree build for the TCP loopback splice module.
# Target: stock distro kernels (initial: running kernel, then 6.17 Ubuntu).
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m += tcp_splice.o
tcp_splice-objs := main.o splice_state.o splice_proto.o splice_ring.o

all: module btf

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Distro headers ship no vmlinux, so kbuild skips module BTF and the kfunc id
# stays unresolved. Resolve it against the running kernel's BTF.
btf: module
	./gen_btf.sh tcp_splice.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f tcp_splice.ko.BTF tcp_splice.ko.BTF_ids

# Convenience targets
load: all
	sudo insmod tcp_splice.ko

unload:
	sudo rmmod tcp_splice

.PHONY: all clean load unload
