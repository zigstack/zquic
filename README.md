# zquic

Pure-Zig QUIC (RFC 9000 / 9001 / 9002), TLS 1.3, HTTP/3, and QPACK. Current release: **[v1.6.10](https://github.com/ch4r10t33r/zquic/releases/tag/v1.6.10)**.

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
    .url = "git+https://github.com/ch4r10t33r/zquic.git?ref=v1.6.10#3f8c8669758bbe57da72017b5db5fd30863e8369",
    .hash = "zquic-1.6.10-2zRc1Il1EwC1WAXVszicLjgivbbHOM8b0yQgvdNYwEyb",
},
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

**Cross-impl (quinn, etc.):** handshake and transfer smoke runs on every PR; the full matrix runs nightly via `.github/workflows/interop-cross-impl.yml`. Recent work (#162) fixed quinn→zquic HTTP/0.9 multiplexing under paced congestion control.

Local interop:

```sh
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-gnu
docker build -t zquic:interop -f interop/Dockerfile.prebuilt .
# then run quic-interop-runner against zquic:interop
```

## Embedder API

The stack is built for [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) HTTP/0.9/HTTP/3, but the same TLS + QUIC core is reusable for custom ALPN and opaque stream I/O (e.g. [zig-libp2p](https://github.com/ch4r10t33r/zig-libp2p)).

| Need | API |
|------|-----|
| Custom ALPN | `ServerConfig.alpn` / `ClientConfig.alpn` |
| Opaque STREAM bytes | `raw_application_streams = true` on both sides; `RawAppStreamSlot` in `raw_app_stream.zig` |
| External UDP loop | `Server.feedPacket`, `Client.feedPacket`, `processPendingWork` |
| Pre-bound socket | `Server.initFromSocket`, `Client.initFromSocket` |
| Heap-allocated client | `Client.initInPlace` (avoids stack-sized return copies in downstream callers) |
| Open/send on streams | `rawAllocateNextLocal*Stream`, `sendRawStreamData` |
| In-memory TLS certs | `cert_pem` / `key_pem` / `client_cert_pem` / `client_key_pem` on config structs (#129) |

Demo `Endpoint` / interop `Server` use small fixed connection arrays (`max_connections` 8 / `MAX_CONNECTIONS` 16) to stay stack-friendly in tests. Production embedders should heap-size their own connection tables via `initFromSocket` + `feedPacket`.

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

- **Linux:** statically linked release binaries; syscalls via `std.os.linux`, no OpenSSL/quictls.
- **macOS:** links `libSystem` (required for supported syscalls and code signing); source remains pure Zig.

## License

MIT
