# Packaging (fixed / appliance kernel)

A single `tcp-splice_<ver>_<arch>.deb` carrying a **prebuilt** kernel module for
one exact kernel, the `tcp-splice-ctl` tool, and a systemd service that loads the
module and applies the policy in `/etc/tcp-splice/config`.

This shape assumes you control the kernel: the `.ko` is built and BTF-resolved
once against that kernel, so the appliance needs no compiler, headers, `dwarves`,
or DKMS. The module's vermagic pins it to that kernel - it refuses to load on any
other, so a wrong-kernel install fails loudly instead of crashing.

## Release flow

Run on a build host (or the 24.04 builder container) **running, or with headers +
`/sys/kernel/btf/vmlinux` for, the appliance kernel**:

```sh
make module          # tcp_splice.ko, with gen_btf.sh resolving the kfunc BTF
                     # ids against the appliance kernel
make ctl             # tcp-splice-ctl, libbpf linked statically (no runtime dep)

# Secure Boot only: sign the module with the kernel/MOK key.
/usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 \
    MOK.priv MOK.der module/tcp_splice.ko

make deb             # stage + dpkg-deb -> tcp-splice_<ver>_<arch>.deb
```

`make deb` does not build or sign - it packages whatever is already in `module/`
and `ctl/`. Useful env vars:

| var | meaning |
|---|---|
| `VERSION` | package version (default: the `VERSION` file) |
| `ARCH` | dpkg arch (default: `dpkg --print-architecture`) |
| `KERNEL_PKG` | optional hard `Depends:` on the kernel image package, e.g. `linux-image-6.17.0-061700-generic` |

## On the appliance

```sh
sudo apt install ./tcp-splice_0.1.0_amd64.deb
# postinst: depmod, enable + (if running the target kernel) start the service
systemctl status tcp-splice
tcp-splice-ctl status
```

Tune `/etc/tcp-splice/config` (ports, busy-poll, ring size) and
`systemctl restart tcp-splice`. Removal disables the service and unloads the
module.

## What's inside

```
/lib/modules/<KVER>/extra/tcp_splice.ko    prebuilt, BTF-resolved, (signed)
/usr/sbin/tcp-splice-ctl                     static libbpf; bpf object baked in
/usr/sbin/tcp-splice-start                   reads config -> modprobe + ctl enable
/lib/systemd/system/tcp-splice.service
/etc/tcp-splice/config                       conffile (survives upgrades)
```

For varied / customer-managed kernels instead, this would be a DKMS package that
rebuilds per kernel; see the project notes. The fixed-kernel deb here is simpler
and needs no toolchain on the target.
