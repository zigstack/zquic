# zquic

A pure-Zig implementation of the QUIC transport protocol (RFC 9000 / 9001 / 9002) with full HTTP/3 and QPACK support.

[![CI](https://github.com/ch4r10t33r/zquic/actions/workflows/ci.yml/badge.svg)](https://github.com/ch4r10t33r/zquic/actions/workflows/ci.yml)

## Protocol Coverage

| RFC | Title | Status |
|-----|-------|--------|
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC: A UDP-Based Multiplexed and Secure Transport | ✅ Complete |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS to Secure QUIC | ✅ Complete |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC Loss Detection and Congestion Control | ✅ Complete |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 | ✅ Complete |
| [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) | QPACK: Header Compression for HTTP/3 | ✅ Complete |
| [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) | QUIC Version 2 | ✅ Complete |

### Frame support

| Frame | Type | Status |
|-------|------|--------|
| PADDING / PING | 0x00–0x01 | ✅ |
| ACK / ACK-ECN | 0x02–0x03 | ✅ |
| RESET_STREAM | 0x04 | ✅ |
| STOP_SENDING | 0x05 | ✅ |
| CRYPTO | 0x06 | ✅ |
| NEW_TOKEN | 0x07 | ✅ |
| STREAM | 0x08–0x0f | ✅ |
| MAX_DATA | 0x10 | ✅ |
| MAX_STREAM_DATA | 0x11 | ✅ |
| MAX_STREAMS (bidi/uni) | 0x12–0x13 | ✅ |
| DATA_BLOCKED | 0x14 | ✅ |
| STREAM_DATA_BLOCKED | 0x15 | ✅ |
| STREAMS_BLOCKED | 0x16–0x17 | ✅ |
| NEW_CONNECTION_ID | 0x18 | ✅ |
| RETIRE_CONNECTION_ID | 0x19 | ✅ |
| PATH_CHALLENGE / PATH_RESPONSE | 0x1a–0x1b | ✅ |
| CONNECTION_CLOSE (transport/app) | 0x1c–0x1d | ✅ |
| HANDSHAKE_DONE | 0x1e | ✅ |

## Interop Results

All 13/13 [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) test cases pass:

| Test | Status |
|------|--------|
| `handshake` | ✅ |
| `transfer` | ✅ |
| `retry` | ✅ |
| `chacha20` | ✅ |
| `keyupdate` | ✅ |
| `resumption` | ✅ |
| `zerortt` | ✅ |
| `http3` | ✅ |
| `connectionmigration` | ✅ |
| `multiplexing` | ✅ |
| `v2` | ✅ |
| `ecn` | ✅ |
| `rebind-port` | ✅ |

## Implementation notes

- **Version negotiation:** Incoming Version Negotiation packets are handled in `Connection.handleVersionNegotiation` (client must see QUIC v1 in the list). Compatible upgrade to QUIC v2 is implemented in the transport I/O layer when the server’s Initial uses v2 (see `io.zig` and `connection.zig` tests).
- **Demo `Endpoint` (`src/transport/endpoint.zig`) and `Server` (`src/transport/io.zig`):** `max_connections` (8) and `MAX_CONNECTIONS` (16) are small fixed arrays so the structs stay stack-friendly for samples, tests, and interop. These are **not protocol caps** — production embedders use `Server.initFromSocket` + `feedPacket` with their own heap-allocated connection map sized to their workload (see "Embedder guide" below).
- **Random bytes:** Connection IDs, stateless reset tokens, and path challenge data use the OS-backed CSPRNG (`std.crypto.random`), not time-seeded PRNGs.
- **Path MTU (RFC 9000 §14):** DPLPMTUD probing is not implemented. You can set `max_udp_payload` on `ServerConfig` / `ClientConfig`; the stack clamps it to \[1200, 65527\] bytes and sizes HTTP/0.9 and HTTP/3 STREAM chunks from that limit (see `transport/path_mtu.zig`).

## Performance

Loopback throughput benchmark on Apple Silicon (M-series Mac), comparing zquic
against [quiche](https://github.com/cloudflare/quiche) (Cloudflare, Rust/BoringSSL) and
[ngtcp2](https://github.com/ngtcp2/ngtcp2) (C/quictls). All built with release
optimizations; steady-state averages (runs 3–5), 5 runs per data point.

| Transfer | zquic | quiche | ngtcp2 | Notes |
|----------|------:|-------:|-------:|-------|
| 1 MB | **351 Mbps** | 256 Mbps | 229 Mbps | zquic leads: fast handshake + protocol efficiency |
| 10 MB | 1,127 Mbps | 1,153 Mbps | **1,359 Mbps** | All three competitive at medium transfers |
| 50 MB | 1,538 Mbps | 1,800 Mbps | **2,371 Mbps** | ngtcp2 leads with assembly AES-GCM |
| 100 MB | 2,008 Mbps | 1,842 Mbps | **3,011 Mbps** | ngtcp2 leads; zquic edges out quiche |

**Key takeaways:**
- zquic **leads at small transfers** (+37% over quiche, +53% over ngtcp2 at 1 MB) thanks to cached AES key schedules, zero FFI overhead, and batched client receives.
- At medium-to-large transfers all three are competitive, with ngtcp2 pulling ahead due to quictls's hand-tuned assembly AES-GCM.
- zquic stays ahead of or even with quiche across all transfer sizes.

Reproduce with:
```sh
# Quick self-benchmark
zig build bench-e2e -Doptimize=ReleaseFast -- --size-mb 50

# Two-way comparative benchmark (requires Rust toolchain for quiche)
bash bench/local_compare.sh zquic quiche

# Three-way benchmark (also requires cmake + libev for ngtcp2)
SIZE_MB=100 RUNS=5 bash bench/local_compare.sh zquic quiche ngtcp2
```

## Requirements

- Zig **0.16.x**

## Building

```sh
zig build               # build library + server/client binaries
zig build test          # run all 141 unit tests
zig build examples      # build the example programs
```

## Examples

```sh
zig build examples
./zig-out/bin/echo_server        # crypto primitives walkthrough
./zig-out/bin/parse_packet       # parse a QUIC Initial packet header
./zig-out/bin/session_resumption # session tickets and 0-RTT key derivation
```

### Derive Initial secrets (RFC 9001 §5.2)

```zig
const zquic = @import("zquic");
const crypto_keys = zquic.crypto.keys;
const types = zquic.types;

const dcid = try types.ConnectionId.fromSlice(&[_]u8{
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
});
const secrets = crypto_keys.InitialSecrets.derive(dcid.slice());
// secrets.client.key  — AES-128-GCM write key
// secrets.client.iv   — AEAD base IV
// secrets.client.hp   — header protection key
```

### Encode / decode a variable-length integer (RFC 9000 §16)

```zig
const varint = zquic.varint;

var buf: [8]u8 = undefined;
const encoded = try varint.encode(&buf, 15293); // → 2 bytes: 0x7b 0xbd
const decoded = try varint.decode(encoded);
// decoded.value == 15293
```

### Parse a Long Header packet

```zig
const header_mod = zquic.packet.header;

const result = try header_mod.parseLong(raw_bytes);
// result.header.packet_type  — .initial / .handshake / .zero_rtt / .retry
// result.header.dcid         — ConnectionId
// result.header.version      — u32
// result.consumed            — bytes consumed
```

### AES-128-GCM encrypt / decrypt

```zig
const aead_mod = zquic.crypto.aead;

var ciphertext: [plaintext.len + 16]u8 = undefined;
try aead_mod.encryptAes128Gcm(&ciphertext, plaintext, aad, key, nonce);

var recovered: [plaintext.len]u8 = undefined;
try aead_mod.decryptAes128Gcm(&recovered, &ciphertext, aad, key, nonce);
```

### Session tickets and 0-RTT

```zig
const session = zquic.crypto.session;

var store = session.TicketStore{};
store.store(ticket);

if (store.get(now_ms)) |t| {
    const keys = session.deriveEarlyKeys(t);
    // keys.key / keys.iv / keys.hp  — ready for 0-RTT AEAD
}
```

### HTTP/3 framing

```zig
const h3 = zquic.http3.frame;

var buf: [256]u8 = undefined;
const written = try h3.writeFrame(&buf, @intFromEnum(h3.FrameType.headers), encoded_header_block);

const result = try h3.parseFrame(buf[0..written]);
// result.frame.headers.data / result.frame.data / result.frame.settings …
```

## Module Map

```
src/
  varint.zig              Variable-length integer codec (RFC 9000 §16)
  types.zig               ConnectionId, StreamId, TransportError, …
  packet/
    header.zig            Long/Short header parse + serialize
    number.zig            Packet number encode/decode (RFC 9000 §A.3)
    packet.zig            Initial, Retry, Version Negotiation builders
    retry.zig             Retry integrity tag (RFC 9001 §5.8)
    version_negotiation.zig  Version Negotiation parse/build
  crypto/
    keys.zig              HKDF-Expand-Label, Initial secret derivation, key update
    aead.zig              AES-128-GCM + ChaCha20-Poly1305, header protection
    initial.zig           Initial packet protect/unprotect helpers
    quic_tls.zig          QUIC-TLS adapter (nonblock ↔ CRYPTO frames)
    session.zig           Session tickets, PSK store, 0-RTT key derivation
    key_update.zig        Key update (RFC 9001 §6), KeyPhaseState
  frames/
    frame.zig             Frame union + parseOne dispatcher
    ack.zig               ACK frame with ECN
    crypto_frame.zig      CRYPTO frame
    stream.zig            STREAM frame
    transport.zig         RESET_STREAM, STOP_SENDING, MAX_DATA, PATH_CHALLENGE, …
  transport/
    io.zig                UDP event loop: server + client, HTTP/0.9 + HTTP/3 I/O
    connection.zig        Connection state machine + ACK manager
    endpoint.zig          UDP socket dispatch
    stream_manager.zig    Stream multiplexing + in-order receive buffer
    flow_control.zig      Connection + stream flow control
    migration.zig         Path validation, connection migration (RFC 9000 §9)
  loss/
    recovery.zig          RTT estimation (SRTT/RTTVAR), PTO, packet-threshold loss detection
    congestion.zig        New Reno congestion control (cwnd, ssthresh, slow start / CA / recovery)
  http09/
    server.zig            HTTP/0.9 request parser + path resolver
    client.zig            HTTP/0.9 request builder + download path helper
  http3/
    frame.zig             HTTP/3 frame codec (RFC 9114 §7)
    qpack.zig             QPACK: static table, dynamic table (RFC 9204)
  cmd/
    server.zig            QUIC server binary
    client.zig            QUIC client binary
vendor/tls/               ianic/tls.zig @ 34248f38c189 (locally patched for Zig 0.16)
interop/
  Dockerfile              Self-contained local build
  Dockerfile.prebuilt     CI-optimised image from pre-built binaries
  run_endpoint.sh         quic-interop-runner entry point
examples/
  echo_server.zig         Crypto primitives walkthrough
  parse_packet.zig        Parse a QUIC Initial packet
  session_resumption.zig  Session tickets and 0-RTT
```

## Embedder guide

The `transport.io` server and client are oriented around the quic-interop-runner HTTP/0.9 and
HTTP/3 paths. The APIs below let other protocols reuse the same TLS 1.3 + QUIC stack (custom
ALPN, opaque stream bytes, external UDP loops).

### Custom ALPN

- `ServerConfig.alpn` and `ClientConfig.alpn` — when set, that exact string is sent in the TLS
  handshake (single protocol). It takes precedence over `http3` / `http09`.
- `serverTlsAlpn(&ServerConfig)` and `clientTlsAlpn(&ClientConfig)` — effective ALPN for the
  handshake (including the HTTP defaults when `alpn` is null).

### Raw application STREAM data

When `raw_application_streams` is true on **both** `ServerConfig` and `ClientConfig`:

- Incoming STREAM frames are appended to per-stream `RawAppStreamSlot` buffers as opaque bytes
  (`handleRawApplicationStreamServer` / `handleRawApplicationStreamClient`). No HTTP/0.9 or
  HTTP/3 parsing is performed.
- Data is merged using the same contiguous-offset rules as the HTTP/3 download path (duplicates
  and gaps are handled conservatively).

Use `rawAppRecvBuffer` / `Client.rawAppRecvBuffer` for a `[]const u8` view of accumulated data
(same backing store as the slot; consume or copy before the slot is reused). This path is for
embedders that drive their own framing on top of QUIC streams.

### External UDP / embedder recv loops

- `Server.feedPacket(buf, src)` — dispatch one datagram without `recvfrom` (e.g. shared UDP port).
- `Server.processPendingWork()` — PTO, flush pending HTTP/raw sends, `flushSendBatch`, reap connections (call after draining injected packets).
- `Server.initFromSocket(allocator, config, sock, take_ownership)` — use a pre-bound IPv4 UDP socket; when `take_ownership` is false, `deinit` does not close the fd.
- `Client.feedPacket(buf)` — inject one datagram.
- `Client.processPendingWork(server_addr)` — Initial/Finished retransmits when the embedder owns the poll loop.
- `Client.initFromSocket` — same ownership semantics as the server.

### Opening streams and sending data (non-HTTP)

- `try rawAllocateNextLocalUniStream` / `try rawAllocateNextLocalBidiStream` on `ConnState` — RFC 9000 §2.1 local stream IDs; returns `error.StreamLimitExceeded` if the peer’s `MAX_STREAMS` / transport-parameter budget is exhausted (do not mix with HTTP streams on the same connection).
- `Server.sendRawStreamData(server, conn, stream_id, offset, data, fin)` and `Client.sendRawStreamData(...)` — send one STREAM frame on 1-RTT; the embedder tracks per-stream offsets.

Dependents import the package module `zquic` from `build.zig.zon`; it imports vendored `tls` as `tls`.

## TLS Integration

QUIC uses TLS 1.3 without the TLS record layer (RFC 9001). A thin adapter in
`src/crypto/quic_tls.zig` strips/adds the 5-byte TLS record header so raw
handshake bytes flow through QUIC CRYPTO frames. The vendored
[ianic/tls.zig](https://github.com/ianic/tls.zig) `nonblock` API is used.

## Releases

See [CHANGELOG.md](CHANGELOG.md) for version history. Releases are published
automatically on `v*` tags via `.github/workflows/release.yml`.

## License

MIT
