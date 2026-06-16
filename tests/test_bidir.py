#!/usr/bin/env python3
"""test_bidir.py - bidirectional-write deadlock-avoidance test.

Both ends of a co-located TCP pair issue send() *before* either calls recv().
That is the classic pattern that deadlocks under a synchronous rendezvous (each
side blocking in send until the peer reads). The ring must let both writes
complete on their own, so that when each side then reads it finds the peer's
bytes. If a regression makes send wait for the peer's recv, both send threads
hang and this test reports a deadlock instead of blocking forever.

This test only exercises the data path; load tcp_splice.ko and configure
tcp-splice-ctl so that loopback and the test PORT are covered before running it.
Ported from the kernel selftest run_bidir_write() in
tools/testing/selftests/bpf/prog_tests/tcp_splice.c.

Run from the repo root (`make test`) or directly. Tunable via PORT.
"""
import os
import socket
import sys
import threading

PORT = int(os.environ.get("PORT", "54321"))
CLIENT_BANNER = b"client-banner"
SERVER_BANNER = b"server-banner"
SEND_TIMEOUT = 5.0   # a deadlock shows up as a send that never returns
RECV_TIMEOUT = 5.0


def make_pair(port):
    """Create a loopback connection, return (client, server-accepted)."""
    lst = socket.socket()
    lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(("127.0.0.1", port))
    lst.listen(1)
    cli = socket.create_connection(("127.0.0.1", port))
    srv, _ = lst.accept()
    lst.close()
    return cli, srv


def sender(sock, data, errors, key):
    try:
        sock.sendall(data)
    except OSError as e:
        errors[key] = e


def main():
    cli, srv = make_pair(PORT)
    try:
        # Both sides write first, neither reads yet. Both sends must return
        # within bounded time (no deadlock).
        errors = {}
        threads = [
            threading.Thread(target=sender, args=(cli, CLIENT_BANNER, errors, "client"),
                             daemon=True),
            threading.Thread(target=sender, args=(srv, SERVER_BANNER, errors, "server"),
                             daemon=True),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(SEND_TIMEOUT)

        if any(t.is_alive() for t in threads):
            print("FAIL: bidirectional send deadlocked (a write never returned)",
                  file=sys.stderr)
            return 1
        if errors:
            print(f"FAIL: send error: {errors}", file=sys.stderr)
            return 1

        # Now read on each side. Each should see exactly the peer's banner.
        cli.settimeout(RECV_TIMEOUT)
        srv.settimeout(RECV_TIMEOUT)
        try:
            got_client = cli.recv(64)   # what the server wrote
            got_server = srv.recv(64)   # what the client wrote
        except socket.timeout:
            print("FAIL: recv timed out (peer's write did not arrive)", file=sys.stderr)
            return 1

        if got_client != SERVER_BANNER:
            print(f"FAIL: client got {got_client!r}, expected {SERVER_BANNER!r}",
                  file=sys.stderr)
            return 1
        if got_server != CLIENT_BANNER:
            print(f"FAIL: server got {got_server!r}, expected {CLIENT_BANNER!r}",
                  file=sys.stderr)
            return 1

        print("PASS: bidirectional write completed without deadlock, banners crossed")
        return 0
    finally:
        cli.close()
        srv.close()


if __name__ == "__main__":
    sys.exit(main())
