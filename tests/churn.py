#!/usr/bin/env python3
# churn.py - stress the splice pairing registry with rapid short-lived loopback
# connections. Each client connects, sends a unique token, the server echoes it,
# the client verifies. Heavy connect/close churn forces ephemeral-port reuse and
# overlapping setup/teardown - the condition for the teardown/pair race. A
# mis-pair surfaces as a timeout, EOF, or echo mismatch.
#
# Usage: churn.py [threads] [iters]   (defaults 64 x 300)
import socket, threading, sys, os, time

THREADS = int(sys.argv[1]) if len(sys.argv) > 1 else 64
ITERS = int(sys.argv[2]) if len(sys.argv) > 2 else 300
HOST = "127.0.0.1"

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, 0))
PORT = srv.getsockname()[1]
srv.listen(512)

stop = False
errors = [0]
mismatch = [0]
ok = [0]
samples = []
lock = threading.Lock()


def server():
    while not stop:
        try:
            c, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def handle(c):
    try:
        c.settimeout(3)
        d = c.recv(64)
        if d:
            c.sendall(d)          # echo back what the client sent
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


def worker(wid):
    for i in range(ITERS):
        tok = f"T{wid:03d}{i:08d}X".encode()   # unique per (worker,iter)
        try:
            c = socket.socket()
            c.settimeout(3)
            c.connect((HOST, PORT))
            c.sendall(tok)
            r = b""
            while len(r) < len(tok):
                chunk = c.recv(64)
                if not chunk:
                    break
                r += chunk
            c.close()
            if r == tok:
                with lock:
                    ok[0] += 1
            else:
                with lock:
                    mismatch[0] += 1            # wrong/short data => mis-pair
                    if len(samples) < 8:
                        samples.append((tok, r))
        except OSError:
            with lock:
                errors[0] += 1                 # timeout/reset/EOF => broken pair


st = threading.Thread(target=server, daemon=True)
st.start()
time.sleep(0.2)

t0 = time.time()
ts = [threading.Thread(target=worker, args=(w,)) for w in range(THREADS)]
for t in ts:
    t.start()
for t in ts:
    t.join()
stop = True
dt = time.time() - t0
try:
    srv.close()
except OSError:
    pass

total = THREADS * ITERS
print(f"conns={total} ok={ok[0]} errors={errors[0]} mismatch={mismatch[0]} "
      f"({total/dt:.0f} conn/s)")
for sent, got in samples:
    print(f"  sent={sent!r} got={got!r}")
sys.exit(1 if (errors[0] or mismatch[0]) else 0)
