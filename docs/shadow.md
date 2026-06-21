# Running zquic under the Shadow network simulator

[Shadow](https://shadow.github.io/) is a discrete-event network simulator
widely used by the Tor project and (increasingly) by QUIC implementations for
**deterministic, repeatable** interop testing: bit-exact reproducibility of
multi-peer scenarios, no NIC variance, no scheduler jitter, no host clock
drift. Shadow can host hundreds–thousands of simulated peers on one box,
which is useful for mesh-scale interop without a real cluster.

## What changes vs. the default build

Shadow's shim intercepts syscalls at the **libc layer** via `LD_PRELOAD`. The
default zquic Linux build is pure-Zig — no libc, raw `std.os.linux.*`
syscalls — which the shim cannot intercept. The `-Dshadow=true` build flag
flips three knobs:

1. **Forces `link_libc = true` on Linux** so the binary is dynamically linked
   against glibc.
2. **Routes `clock_gettime` / `getrandom` through libc** (via
   `compat.zig`'s `!builtin.link_libc` gates) so Shadow's virtual clock and
   deterministic randomness apply.
3. **Disables the `sendmmsg(2)` / `recvmmsg(2)` batched-I/O path** in
   `transport/batch_io.zig`; the per-message `sendto` / `recvfrom` fallback
   is used instead, which Shadow's shim handles.

## Build

```sh
zig build -Dtarget=x86_64-linux-gnu -Dshadow=true -Doptimize=ReleaseSafe
```

Use `-Dtarget=x86_64-linux-gnu` (system glibc) — Shadow's shim is not
compatible with statically-linked musl binaries. Verify with `file`:

```
$ file zig-out/bin/server
… ELF 64-bit LSB executable, x86-64, … dynamically linked,
   interpreter /lib64/ld-linux-x86-64.so.2 …
```

The default (no `-Dshadow`) Linux build remains the fully-static
no-libc binary — no behavior change for non-Shadow consumers.

## Minimal Shadow simulation

Two zquic peers on a 10 Mbps / 15 ms-RTT path:

```yaml
# shadow.yaml
general:
  stop_time: 60s

network:
  graph:
    type: 1_gbit_switch

hosts:
  server:
    network_node_id: 0
    processes:
      - path: ./zig-out/bin/server
        args: --port 4443 --cert test/fixtures/quic_loopback/cert.pem --key test/fixtures/quic_loopback/key.pem
        start_time: 1s

  client:
    network_node_id: 0
    processes:
      - path: ./zig-out/bin/client
        args: server:4443
        start_time: 5s
```

Run:

```sh
shadow shadow.yaml
```

## Known limitations

- **Per-message I/O only**: the batched `sendmmsg`/`recvmmsg` path is
  disabled under Shadow, so throughput inside the simulator is bounded by
  per-packet syscall cost rather than NIC. This is the right trade-off
  for interop / correctness testing; not a fit for performance studies.
- **No `io_uring`**: zquic does not use it anyway.
- **TLS RNG determinism**: with `-Dshadow=true`, `getrandom` goes through
  libc and is virtualized by Shadow's shim. RNG output is therefore
  deterministic across runs with the same Shadow seed — useful for
  reproducing handshake-level bugs.

## Status

Phase 1: Build flag + syscall-routing changes (this commit). Phase 2 (out of
scope here): bundled Shadow Docker image + CI matrix entry. Tracking: #216.
