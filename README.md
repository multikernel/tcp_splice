# TCP Splice

An out-of-tree Linux kernel module that accelerates **co-located TCP** (loopback
and same-host container sidecars) by splicing two locally-connected TCP sockets
through a small in-kernel ring, bypassing the skb/softirq/TCP-receive path for
bulk data while leaving the real TCP connection intact.

## How it works

It is the loadable-module form of the in-tree `bpf_sock_splice_pair()` prototype.
A `sock_ops` BPF program calls the module's kfunc from each endpoint's
ESTABLISHED callback, and the module pairs the two ends of the connection through
a private global registry (**no sockmap**).

Once both ends are paired:

- The ring is the **sole** data path for `sendmsg`/`recvmsg`. There is no
  per-write fallback to TCP, so a full ring backpressures the sender as ordinary
  stream flow control (like a full send buffer).
- A ring byte can never overtake TCP data, so the splice never reorders the
  stream. Only the brief startup window before the second end pairs carries data
  over TCP: the sender records the one sequence number where it switches to the
  ring (`ring_seq`), and the receiver delivers all startup TCP up to that point
  before draining the ring.
- Sequence numbers stay frozen at post-handshake values, so FIN/RST/keepalive
  keep working over normal TCP and the pair tears down on a regular close.

## Performance

The win scales with how network-bound the workload is. The larger a fraction of
each operation is the co-located hop (rather than userspace work in the server),
the more the ring removes. Numbers below are `netperf` (synthetic, near-zero
server work) and `redis-benchmark` (a real, thin server), baseline TCP vs. the
splice path, sender and receiver pinned to adjacent CPUs. Loopback is
`127.0.0.1`; "container" is two network namespaces over a veth pair plus a Linux
bridge.

**TCP_RR (request/response), transactions/sec, the headline case:**

| msg size | loopback baseline | splice | splice + busy-poll |
|---|---|---|---|
| 1 B   | 110.2k | 267.0k (2.4x) | 1113.8k (**10.0x**) |
| 64 B  | 111.6k | 265.7k (2.4x) | 1073.3k (9.6x) |
| 1 KB  | 105.8k | 235.1k (2.2x) |  713.0k (**6.7x**) |
| 16 KB |  40.5k |  89.6k (2.2x) |  123.7k (3.1x) |
| 64 KB |  17.8k |  20.9k (1.2x) |   40.5k (2.3x) |

Container TCP_RR tracks loopback closely (e.g. 1 KB: 100.4k → 233.9k → 704.9k).
The busy-poll budget is off by default; see [Busy polling](#busy-polling).

**TCP_STREAM (bulk), Mbit/s.** Roughly neutral on bare-metal loopback (kernel TSO
already amortizes per-packet cost), but a large win container-to-container, where
the per-skb veth+bridge cost is exactly what the ring sidesteps:

| msg size | container baseline | splice |
|---|---|---|
| 1 KB |  3710 | 21326 (**5.8x**) |
| 4 KB |  8084 | 48834 (**6.0x**) |
| 16 KB | 26083 | 27788 (1.1x) |

These match the in-tree prototype and are reproduced by this module on the same
hardware (1 KB loopback RR: 95.7k → 223.7k → 715.5k).

**Redis (application level), GET ops/sec, container-to-container.** A real thin
datastore spends only a few microseconds of userspace per op (command parse, hash
lookup, reply encode), so the co-located network hop is a large fraction of each
request and the ring removes most of it. `redis-benchmark` against `redis-server`,
two containers over the veth+bridge:

| concurrency | baseline | splice |
|---|---|---|
| `-c 1` (latency-bound) |  35k |  85k (**2.5x**) |
| `-c 50` (saturated)    | 131k | 214k (1.6x) |

At `-c 1` the per-GET round trip drops from ~29 µs to ~12 µs. The win is below the
synthetic container TCP_RR above because even Redis's few microseconds of per-op
work dilute the network saving; the speedup tracks the inverse of per-op userspace
cost, so a heavier server (for example an L7 proxy) sees less. Busy-poll adds
nothing here because Redis is epoll-driven and never enters the ring's
blocking-recv spin (see [Busy polling](#busy-polling)).

## Requirements

- A kernel built with `CONFIG_DEBUG_INFO_BTF` (for `/sys/kernel/btf/vmlinux`) and
  `CONFIG_BPF_SYSCALL`.
- For `module/`: matching `linux-headers`, `pahole` (dwarves), `binutils`.
- For `bpf/` + `ctl/`: `clang`, `bpftool`, and `libbpf` headers (`libbpf-dev`).

## Build

Each component has its own Makefile; the top level drives all three:

```sh
make            # module + bpf + ctl
make module     # just the kernel module
make bpf        # just the sock_ops object (+ skeleton)
make ctl        # just the control tool (consumes the bpf skeleton)
```

`make module` builds the `.ko` and then runs `gen_btf.sh`. That extra BTF step
is required because distro `-headers` packages ship no `vmlinux`, so kbuild skips
module BTF and the kfunc's BTF id stays unresolved (the kfunc would fail to
register). `gen_btf.sh` resolves it against the running kernel's
`/sys/kernel/btf/vmlinux` via `pahole` + `resolve_btfids` + `objcopy`.

## Load

```sh
sudo insmod module/tcp_splice.ko      # or: make -C module load
# dmesg: "tcp_splice: loaded, bpf_tcp_splice_pair registered"
sudo rmmod tcp_splice                 # or: make -C module unload
```

A loaded BPF program that uses the kfunc pins the module, so `rmmod` is blocked
while any paired socket is live.

## Usage

The module is only the data plane; a `sock_ops` program decides which
connections to splice. `tcp-splice-ctl` loads that program, sets the policy, and
attaches it to a cgroup. Both endpoints of a connection must fall under the
attached cgroup (see [Pairing requirements](#pairing-requirements)), so attach at
a level that covers them. The cgroup-v2 root covers everything:

```sh
# enable for everything under the cgroup-v2 root, loopback flows only, port 6379
sudo ctl/tcp-splice-ctl enable --cgroup /sys/fs/cgroup --loopback-only --ports 6379

sudo ctl/tcp-splice-ctl status
# tcp_splice: enabled (loopback_only=1, ports=6379)

sudo ctl/tcp-splice-ctl disable
```

Options for `enable`:

| option | meaning |
|---|---|
| `--cgroup PATH` | cgroup-v2 directory to attach to (required) |
| `--loopback-only` | only splice loopback flows (`127.0.0.0/8`, `::1`) |
| `--ports a,b,c` | only splice flows where either endpoint uses one of these ports (default: any) |
| `--busy-poll-us N` | set the ring busy-poll budget (writes `net.core.busy_read`; see [Busy polling](#busy-polling)) |
| `--ring-kbytes N` | per-direction ring size in KiB (writes the `ring_kbytes` module parameter; see [Ring size](#ring-size)) |

The attachment is a **pinned BPF link** under `/sys/fs/bpf/tcp_splice/`, so it
persists after `tcp-splice-ctl` exits; `disable` removes it. The module must be
loaded first because it provides the kfunc the program calls. `tcp-splice-ctl`
does not write any BPF itself: the `sock_ops` object is built into it from `bpf/`.

## Pairing requirements

Pairing keys two endpoints by a canonical, direction-independent 4-tuple, so the
sock_ops program must call the kfunc on **both** ends (each installs its own
proto under its own lock). For loopback the netns is folded into the key, so two
unrelated `127.0.0.1` connections in different namespaces never mis-pair; for
routable addresses (container veth IPs) the key is netns-agnostic, so the two
ends in *different* namespaces still match. If only one end ever pairs, that
socket simply keeps using plain TCP (the ring is engaged only once both ends are
installed).

## Tuning

### Busy polling

For latency-bound request/response traffic, the splice receiver can spin on the
ring before parking, which collapses the per-cycle wakeup cost. The budget is the
mainline **`net.core.busy_read`** sysctl (microseconds), which seeds `sk_ll_usec`
on every socket:

```sh
sudo sysctl -w net.core.busy_read=50
# or, equivalently, via the control tool:
sudo ctl/tcp-splice-ctl enable --cgroup /sys/fs/cgroup --busy-poll-us 50
```

`0` (default) disables it. An application can also opt in per-socket with
`setsockopt(SO_BUSY_POLL)`.

The spin is on the in-kernel **ring** directly, never on a NAPI instance, which
matters because loopback and veth deliver via the per-CPU backlog and expose no
pollable `napi_id`, so the kernel's generic `sk_busy_loop()` is a no-op for them.
The module only borrows the budget value (`sk_can_busy_loop()`/
`sk_busy_loop_timeout()`), not the NAPI machinery.

### Ring size

The per-direction ring is sized by the `ring_kbytes` module parameter (KiB,
rounded up to a power of two; default **64**):

```sh
# at load time
sudo insmod module/tcp_splice.ko ring_kbytes=256
# or at runtime (applies to connections spliced afterwards)
echo 256 | sudo tee /sys/module/tcp_splice/parameters/ring_kbytes
# or via the control tool
sudo ctl/tcp-splice-ctl enable --cgroup /sys/fs/cgroup --ring-kbytes 256
```

Because the ring is the sole data path (no TCP fallback), the size does **not**
affect the bypass ratio; effectively all payload moves through the ring at any
size. It is purely a flow-control/memory knob: a larger ring lets a fast sender
run further ahead before it blocks on a full ring, at the cost of memory (two
rings per spliced connection). `tcp-splice-ctl status` reports the current value.
