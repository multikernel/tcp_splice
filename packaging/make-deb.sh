#!/bin/sh
# Package the prebuilt tcp_splice artifacts into a single .deb for a fixed
# (appliance) kernel. This does NOT build or sign anything - it stages whatever
# is already in module/ and ctl/. The release flow is:
#
#   1. build module/tcp_splice.ko for the appliance kernel, with gen_btf.sh
#      having resolved the kfunc BTF ids against THAT kernel (make module, run
#      on a host/container with the appliance kernel's /sys/kernel/btf/vmlinux);
#   2. build ctl/tcp-splice-ctl with libbpf statically linked (no runtime dep);
#   3. sign module/tcp_splice.ko if Secure Boot is enforced
#      (scripts/sign-file sha256 <key> <crt> module/tcp_splice.ko);
#   4. run this script (or: make deb).
#
# Env: VERSION (pkg version), ARCH (dpkg arch), KERNEL_PKG (optional hard
# Depends on the kernel image package, e.g. linux-image-6.17.0-061700-generic).
set -e

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

VERSION=${VERSION:-$(cat VERSION 2>/dev/null || echo 0.1.0)}
ARCH=${ARCH:-$(dpkg --print-architecture 2>/dev/null || echo amd64)}
KO=module/tcp_splice.ko
CTL=ctl/tcp-splice-ctl

[ -f "$KO" ]  || { echo "make-deb: missing $KO (run: make module)"  >&2; exit 1; }
[ -f "$CTL" ] || { echo "make-deb: missing $CTL (run: make ctl)"    >&2; exit 1; }

# The kernel this module targets, taken from its own vermagic.
KVER=$(modinfo -F vermagic "$KO" 2>/dev/null | awk '{print $1}')
[ -n "$KVER" ] || { echo "make-deb: cannot read vermagic from $KO" >&2; exit 1; }

# Warn (do not fail) if the module looks unsigned - fine without Secure Boot.
if ! modinfo "$KO" 2>/dev/null | grep -q '^sig_id:'; then
	echo "make-deb: note: $KO is unsigned (ok unless Secure Boot is enforced)" >&2
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

install -D -m644 "$KO"  "$STAGE/lib/modules/$KVER/extra/tcp_splice.ko"
install -D -m755 "$CTL" "$STAGE/usr/sbin/tcp-splice-ctl"
install -D -m755 packaging/tcp-splice-start   "$STAGE/usr/sbin/tcp-splice-start"
install -D -m644 packaging/tcp-splice.service "$STAGE/lib/systemd/system/tcp-splice.service"
install -D -m644 packaging/tcp-splice.conf    "$STAGE/etc/tcp-splice/config"

mkdir -p "$STAGE/DEBIAN"
if [ -n "$KERNEL_PKG" ]; then
	DEPENDS="Depends: $KERNEL_PKG"
else
	DEPENDS=""
fi
sed -e "s|@VERSION@|$VERSION|g" \
    -e "s|@ARCH@|$ARCH|g" \
    -e "s|@KVER@|$KVER|g" \
    packaging/deb/control.in \
	| { if [ -n "$DEPENDS" ]; then sed "s|@DEPENDS@|$DEPENDS|"; else sed "/@DEPENDS@/d"; fi; } \
	> "$STAGE/DEBIAN/control"
sed -e "s|@KVER@|$KVER|g" packaging/deb/postinst > "$STAGE/DEBIAN/postinst"
cp packaging/deb/prerm     "$STAGE/DEBIAN/prerm"
cp packaging/deb/conffiles "$STAGE/DEBIAN/conffiles"
chmod 755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"

OUT="tcp-splice_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT" >/dev/null
echo "built $OUT  (kernel $KVER, arch $ARCH)"
