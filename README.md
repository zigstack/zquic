# zquic

Pure-Zig QUIC (RFC 9000 / 9001 / 9002), TLS 1.3, HTTP/3, and QPACK. Current release: **[v1.7.48](https://github.com/ch4r10t33r/zquic/releases/tag/v1.7.48)**.

[![CI](https://github.com/ch4r10t33r/zquic/actions/workflows/ci.yml/badge.svg)](https://github.com/ch4r10t33r/zquic/actions/workflows/ci.yml)

## Requirements

- Zig **0.16.x**

## Quick start

```sh
zig build                 # library + server/client binaries
zig build test            # unit tests
zig build examples        # example programs
```

Import as a package dependency (`build.zig.zon`):

```zig
.zquic = .{
    .url = "https://github.com/ch4r10t33r/zquic/archive/refs/tags/v1.7.48.tar.gz",
    .hash = "zquic-1.7.0-2zRc1PSAFgDCESpm-vZsUr4O02HM0dpzmVJSx5WXW6ES",
},
```

Or fetch the latest tag automatically:

```sh
zig fetch --save "https://github.com/ch4r10t33r/zquic/archive/refs/tags/v1.7.48.tar.gz"
```

See [CHANGELOG.md](CHANGELOG.md) for release notes. Tags publish Linux amd64 binaries via `.github/workflows/release.yml`.

## Protocol coverage

| RFC | Title | Status |
|-----|-------|--------|
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC transport | ✅ |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | TLS for QUIC | ✅ |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | Loss detection & congestion control | ✅ |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 | ✅ |
| [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) | QPACK | ✅ |
| [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) | QUIC v2 | ✅ |

All standard QUIC frame types, flow control, migration, key update, 0-RTT/resumption, ECN, and connection IDs are implemented. DPLPMTUD probing lives in `src/transport/path_mtu.zig`.

## Interop

**zquic ↔ zquic:** all 13 [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) cases pass on CI (`handshake`, `transfer`, `retry`, `chacha20`, `keyupdate`, `resumption`, `zerortt`, `http3`, `connectionmigration`, `multiplexing`, `v2`, `ecn`, `rebind-port`).

**Cross-impl (quinn ↔ zquic):** per-commit CI runs the P0 subset (`handshake`, `transfer` in both directions plus `multiplexing(zquic→quinn)`); the full matrix runs nightly via `.github/workflows/interop-cross-impl.yml` and reclassifies the known capability gaps (HTTP/3, 0-RTT, session resumption, key update, Retry, ChaCha20, port rebinding, quinn-driven multiplexing) as `UNSUPPORTED` rather than failed — see `EXPECTED_UNSUPPORTED` in that workflow for the current list. Recent quinn-interop hardening: `transfer(cross-zquic-quinn)` flow-control regression (#201), per-PN-space loss detector with RFC 9001 §4.9 Initial/Handshake abandonment (#211), CONNECTION_CLOSE retransmission during draining (#194), stateless reset emission with rate-limit + 41-byte trigger floor (#206), NEW_TOKEN issuance + replay (#213).

Local interop:

```sh
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-gnu
docker build -t zquic:interop -f interop/Dockerfile.prebuilt .
# then run quic-interop-runner against zquic:interop
```

## Shadow simulator (`-Dshadow=true`)

zquic builds for the [Shadow network simulator](https://shadow.github.io/), which gives deterministic, bit-exact replays of multi-peer scenarios — no NIC variance, no scheduler jitter. Shadow's shim intercepts at the libc layer via `LD_PRELOAD`, so the default pure-Zig Linux build (raw `std.os.linux.*` syscalls, no libc) is invisible to it; the `-Dshadow=true` flag fixes that:

```sh
zig build -Dtarget=x86_64-linux-gnu -Dshadow=true -Doptimize=ReleaseSafe
file zig-out/bin/server   # → dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2
```

What changes under `-Dshadow=true`:

- `link_libc = true` on Linux — dynamically linked against glibc so the Shadow shim can inject.
- `compat.zig`'s `clock_gettime` and `getrandom` route through libc (gated on `!builtin.link_libc`) so Shadow's virtual clock + deterministic randomness apply.
- `transport/batch_io.zig` disables the `sendmmsg(2)`/`recvmmsg(2)` batched path and falls back to per-message `sendto`/`recvfrom` (Shadow's shim doesn't virtualize the batched syscalls).

See [docs/shadow.md](docs/shadow.md) for a minimal `shadow.yaml` and the known limitations. The default no-libc Linux build is unaffected.

## Embedder API

The stack is built for [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) HTTP/0.9/HTTP/3, but the same TLS + QUIC core is reusable for custom ALPN and opaque stream I/O (e.g. [zig-libp2p](https://github.com/ch4r10t33r/zig-libp2p)).

| Need | API |
|------|-----|
| Custom ALPN | `ServerConfig.alpn` / `ClientConfig.alpn` |
| Opaque STREAM bytes | `raw_application_streams = true` on both sides; `RawAppStreamSlot` in `raw_app_stream.zig` |
| External UDP loop | `Server.feedPacket`, `Client.feedPacket`, `processPendingWork` |
| Pre-bound socket | `Server.initFromSocket`, `Client.initFromSocket` |
| Heap-allocated client | `Client.initInPlace` (avoids stack-sized return copies in downstream callers) |
| Open client-initiated streams | `rawAllocateNextLocalBidiStream` / `rawAllocateNextLocalUniStream` (emit `STREAMS_BLOCKED` on cap-hit, #188 / #205) |
| Open server-initiated streams | `Server.openRawAppStream` (libp2p gossip-over-any-connection, #171) |
| Send / FIN on streams | `sendRawStreamData` (now splits at packet-build time via `sent_in_buf` cursor, #199) |
| In-memory TLS certs | `cert_pem` / `key_pem` / `client_cert_pem` / `client_key_pem` on config structs (#129) |
| Congestion-control profile | `CcOptions.aggressive` opts into the libp2p-tuned 32·MSS IW / 10·MSS floor; default tracks RFC 9002 §7.2 / §7.6.3 (#195) |
| Conn capacity | `MAX_CONNECTIONS = 256`, boxed (quinn-style slab) — heap cost scales with active conns, not the cap (#209) |

Demo `Endpoint` uses a small fixed connection array (`max_connections` 8) to stay stack-friendly in tests. Production embedders should still heap-size their own connection tables via `initFromSocket` + `feedPacket` for unbounded scale.

## Layout

```
src/
  transport/io.zig          Server + client event loop, HTTP/0.9 + HTTP/3
  transport/raw_app_stream.zig   Opaque STREAM reassembly for embedders
  transport/path_mtu.zig    Path MTU limits + DPLPMTUD
  crypto/                   AEAD, keys, QUIC-TLS adapter, session tickets
  loss/                     RTT, loss detection, New Reno (+ CUBIC option)
  http3/  http09/           HTTP layers
  packet/  frames/          Wire codecs
vendor/tls/                 Vendored ianic/tls.zig (Zig 0.16)
interop/                    quic-interop-runner Docker entrypoint
examples/                   Small standalone demos
bench/                      Loopback throughput vs quiche/ngtcp2
```

Varint encoding is re-exported from the shared [`zig-varint`](https://github.com/ch4r10t33r/zig-varint) package.

## Platform notes

- **Linux (default):** statically linked release binaries; syscalls via `std.os.linux`, no OpenSSL/quictls, no libc.
- **Linux (`-Dshadow=true`):** dynamically linked against glibc with libc-mediated syscalls so the [Shadow simulator](#shadow-simulator--dshadowtrue)'s shim can inject. See [docs/shadow.md](docs/shadow.md).
- **macOS:** links `libSystem` (Darwin has no stable syscall ABI); source remains pure Zig.

## Logging (`DEBUG_QUIC`)

zquic emits all diagnostics through Zig's standard logging under the **`.zquic`
scope** (`std.log.scoped(.zquic)`). It never writes to a file or to stderr
directly — the embedder's `std_options.logFn` decides what is rendered and
where.

Under sustained load the transport is *intentionally chatty* at `warn`:
per-stream send backpressure (`pending-stream-send queue full`), congestion/loss
notices, and connection-lost warnings are normal operational signal during
catch-up or when a peer stops reading a stream. On a busy node this floods the
main log, so the recommended convention (mirroring rust-libp2p) is to gate the
`.zquic` scope behind a **`DEBUG_QUIC`** environment variable — **off by
default**, with `err` always passing through so genuine failures stay visible:

```zig
// In your root module:
pub const std_options: std.Options = .{ .logFn = quicAwareLogFn };

var quic_debug = std.atomic.Value(bool).init(false); // set at startup from env

fn quicAwareLogFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    // Gate warn/info/debug for the QUIC scope unless DEBUG_QUIC is set; err
    // always passes through. (Add `.quic_runtime` etc. if you embed zig-libp2p.)
    if (scope == .zquic and
        @intFromEnum(level) >= @intFromEnum(std.log.Level.warn) and
        !quic_debug.load(.monotonic)) return;
    std.log.defaultLog(level, scope, format, args);
}

// At startup:
if (std.posix.getenv("DEBUG_QUIC")) |v| {
    if (std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true")) quic_debug.store(true, .monotonic);
}
```

Run with `DEBUG_QUIC=1` (also accepts `true`/`yes`/`on`) to surface the full
transport log stream when debugging; leave it unset for a quiet main log.
zeam ships exactly this gate (`quicAwareLogFn` in `pkgs/cli/src/main.zig`),
covering both `.zquic` and zig-libp2p's `.quic_runtime` family of scopes.

## Open work

A standing quinn-vs-zquic gap analysis tracks remaining capability deltas:

- **Tracker:** [#138](https://github.com/ch4r10t33r/zquic/issues/138) (closed sub-issues linked from the comment thread).
- **Open at v1.7.48:** RFC 9221 unreliable datagrams (#181), per-stream send buffer abstraction (#184), connection statistics expansion (#186), `ACK_FREQUENCY` extension (#187), stream priority API (#191), BBR congestion controller (#192).
- **Shadow simulator support:** Phase 1 (build flag, syscall routing, batched-I/O fallback) tracked in #216 — Phase 2 (Docker image + CI matrix) is the next step.

## License

MIT
