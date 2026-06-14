#!/bin/sh
# test_loopback.sh - round-trip loopback splice integrity test.
#
# Loads tcp_splice.ko, attaches the sock_ops program via tcp-splice-ctl on the
# root cgroup (loopback-only, restricted to the test port), runs a 1 MiB
# loopback echo transfer, and checks the bytes round-trip intact.
#
# Run from the repo root (`make test`) or directly; needs root, python3, and a
# prior `make` (module + bpf + ctl built).
#
# NOTE: this verifies data *correctness* through the paired path. It does not yet
# assert the splice fast path was taken vs. TCP fallback - that needs a stat
# counter in the module (TODO).
set -eu

cd "$(dirname "$0")/.."

PORT=${PORT:-54321}
BYTES=${BYTES:-1048576}			# 1 MiB
CGROUP=${CGROUP:-/sys/fs/cgroup}	# cgroup v2 root covers all processes
KO=module/tcp_splice.ko
CTL=ctl/tcp-splice-ctl

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
[ -f "$KO" ]  || { echo "build first: $KO missing"  >&2; exit 1; }
[ -x "$CTL" ] || { echo "build first: $CTL missing" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

IN=$(mktemp); OUT=$(mktemp); SRV=""
cleanup() {
	[ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
	"$CTL" disable >/dev/null 2>&1 || true
	rm -f "$IN" "$OUT"
}
trap cleanup EXIT

lsmod | grep -qw tcp_splice || insmod "$KO"
"$CTL" enable --cgroup "$CGROUP" --loopback-only --ports "$PORT"

head -c "$BYTES" /dev/urandom > "$IN"

# echo server: read BYTES, write them back.
python3 - "$PORT" "$BYTES" <<'PY' &
import socket, sys
port, n = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
c, _ = s.accept()
buf = b""
while len(buf) < n:
    d = c.recv(65536)
    if not d: break
    buf += d
c.sendall(buf); c.close()
PY
SRV=$!
sleep 0.5

# client: send IN, collect the echo into OUT.
python3 - "$PORT" "$BYTES" "$IN" "$OUT" <<'PY'
import socket, sys
port, n = int(sys.argv[1]), int(sys.argv[2])
data = open(sys.argv[3], "rb").read()
s = socket.socket(); s.connect(("127.0.0.1", port))
s.sendall(data)
out = b""
while len(out) < n:
    d = s.recv(65536)
    if not d: break
    out += d
open(sys.argv[4], "wb").write(out); s.close()
PY

wait "$SRV" 2>/dev/null || true
SRV=""

if cmp -s "$IN" "$OUT"; then
	echo "PASS: $BYTES bytes round-tripped intact"
	exit 0
fi
echo "FAIL: data mismatch" >&2
exit 1
