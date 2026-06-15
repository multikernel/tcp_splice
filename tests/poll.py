#!/usr/bin/env python3
# poll_repro.py - deterministic reproducer for the splice poll-readiness gap.
#
# A co-located loopback connection: the server sends a response that (once the
# pair is spliced) travels through the ring. The client waits for it using
# either select() (poll(2)-based) or a plain blocking recv().
#
#   - blocking recv() enters the module's recvmsg and waits on the ring -> works.
#   - select() re-evaluates tcp_poll(), which is blind to the ring -> if the
#     response is ring-only, select() times out and the read never happens.
#
# Usage: poll_repro.py <select|blocking>
# Exit 0 = client received the response; 1 = timed out / failed.
import socket, select, sys, threading, time

mode = sys.argv[1] if len(sys.argv) > 1 else "select"
MSG = b"X" * 64
port_holder = []


def server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port_holder.append(s.getsockname()[1])
    s.listen(1)
    c, _ = s.accept()
    c.recv(16)            # wait for the client's request (forces pairing)
    time.sleep(0.5)       # let the pair settle so the response is ring-only
    c.sendall(MSG)        # server -> client: travels via the ring once spliced
    time.sleep(2.0)
    c.close()


t = threading.Thread(target=server, daemon=True)
t.start()
while not port_holder:
    time.sleep(0.01)
port = port_holder[0]

c = socket.socket()
c.connect(("127.0.0.1", port))
c.sendall(b"REQ")
time.sleep(0.2)           # ensure both ends paired before the response

if mode == "select":
    c.setblocking(False)
    r, _, _ = select.select([c], [], [], 5.0)
    if not r:
        print("FAIL: select() timed out - ring data not pollable")
        sys.exit(1)
    data = c.recv(128)
else:  # blocking
    c.settimeout(5.0)
    try:
        data = c.recv(128)
    except socket.timeout:
        print("FAIL: blocking recv() timed out")
        sys.exit(1)

if data == MSG:
    print(f"OK ({mode}): received {len(data)} bytes")
    sys.exit(0)
print(f"FAIL ({mode}): got {len(data)} bytes, expected {len(MSG)}")
sys.exit(1)
