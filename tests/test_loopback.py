#!/usr/bin/env python3
"""test_loopback.py - round-trip loopback splice integrity test.

Runs a 1 MiB loopback echo transfer and checks the bytes round-trip intact.

This test only exercises the data path; it does NOT load the module or configure
the splice. Load tcp_splice.ko and attach the sock_ops program so that loopback
and the test PORT are covered, e.g.

    sudo insmod module/tcp_splice.ko
    sudo /usr/sbin/tcp-splice-ctl enable --cgroup /sys/fs/cgroup --loopback-only --ports 54321

BEFORE running it. Run from the repo root (`make test`) or directly. Tunable via
the PORT and BYTES environment variables.

NOTE: this verifies data *correctness* through the (presumably paired) path. It
does not assert the splice fast path was taken vs. plain TCP; that needs a stat
counter in the module (TODO).
"""
import os
import socket
import sys
import threading
import time

PORT = int(os.environ.get("PORT", "54321"))
BYTES = int(os.environ.get("BYTES", str(1 << 20)))   # 1 MiB


def recv_exactly(sock, n):
    """Read until n bytes arrive or the peer closes."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def echo_server(listen_sock, n):
    """Accept one connection, read n bytes, echo them back."""
    try:
        conn, _ = listen_sock.accept()
        with conn:
            conn.sendall(recv_exactly(conn, n))
    finally:
        listen_sock.close()


def round_trip(port, payload):
    """Send payload to a co-located echo server, return what comes back."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)

    t = threading.Thread(target=echo_server, args=(srv, len(payload)), daemon=True)
    t.start()
    time.sleep(0.1)  # let the listen settle before connecting

    with socket.create_connection(("127.0.0.1", port)) as cli:
        cli.sendall(payload)
        out = recv_exactly(cli, len(payload))
    t.join(5)
    return out


def main():
    payload = os.urandom(BYTES)
    out = round_trip(PORT, payload)
    if out == payload:
        print(f"PASS: {BYTES} bytes round-tripped intact")
        return 0
    print(f"FAIL: data mismatch ({len(out)} of {BYTES} bytes returned)",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
