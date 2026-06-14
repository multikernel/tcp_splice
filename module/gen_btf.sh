#!/bin/sh
# Resolve the module's kfunc BTF ids and emit a *non-distilled* split BTF that
# loads on both distro -headers kernels and full kernel trees.
#
# Two problems this works around:
#   1. Distro -headers ship no vmlinux, so kbuild skips module BTF entirely and
#      the kfunc id in .BTF_ids stays 0 (the kfunc fails to register).
#   2. Full kernel trees + recent pahole emit a *distilled* base BTF (.BTF.base),
#      which some kernels reject (e.g. duplicate types -> "multiple candidates").
# In both cases we (re)generate plain split BTF referencing the base directly.
set -e
KO=${1:-tcp_splice.ko}
KREL=$(uname -r)
KT=/lib/modules/$KREL/build

# Base BTF: a full tree's ELF vmlinux if present, else the running kernel's BTF.
if [ -f "$KT/vmlinux" ]; then
	BASE=$KT/vmlinux
else
	BASE=/sys/kernel/btf/vmlinux
fi
RB=$(ls "$KT/tools/bpf/resolve_btfids/resolve_btfids" \
        "/usr/src/linux-headers-$KREL/tools/bpf/resolve_btfids/resolve_btfids" \
        2>/dev/null | head -1)

[ -e "$BASE" ] || { echo "gen_btf: no base BTF at $BASE (need CONFIG_DEBUG_INFO_BTF)"; exit 1; }
[ -n "$RB" ]  || { echo "gen_btf: resolve_btfids not found";   exit 1; }
command -v pahole >/dev/null || { echo "gen_btf: pahole not installed"; exit 1; }

# Force NON-distilled split BTF. Newer pahole defaults to a distilled base; pass
# an explicit feature list omitting distilled_base when it is supported.
FEAT=""
if pahole --supported_btf_features 2>/dev/null | grep -q distilled_base; then
	FEAT="--btf_features=encode_force,var,float,decl_tag,type_tag,enum64,decl_tag_kfuncs"
fi

# Drop any BTF kbuild already attached (split and/or distilled base), then
# regenerate from the module's DWARF referencing $BASE directly.
objcopy --remove-section .BTF --remove-section .BTF.base "$KO" 2>/dev/null || true
pahole -J $FEAT --btf_base="$BASE" "$KO"
"$RB" -b "$BASE" "$KO"

# With a raw-BTF base, resolve_btfids emits side files instead of patching the
# ELF; splice them back in.
if [ -f "$KO.BTF_ids" ]; then
	objcopy --update-section .BTF_ids="$KO.BTF_ids" "$KO"
	[ -f "$KO.BTF" ] && objcopy --update-section .BTF="$KO.BTF" "$KO"
	rm -f "$KO.BTF_ids" "$KO.BTF"
fi
echo "gen_btf: resolved kfunc BTF ids into $KO (base: $BASE)"
