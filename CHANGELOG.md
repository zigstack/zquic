# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [v1.7.37] - 2026-06-16

### Added

- **Server-initiated raw-app bidirectional streams** (`Server.openRawAppStream`).
  The server can now open a fresh bidi stream to the client and have it
  delivered to the embedder as a raw-app stream, instead of only being able to
  write on an already client-opened stream. `openRawAppStream` allocates the
  next server-initiated bidi id (RFC 9000 §2.1 parity `% 4 == 1`, honoring the
  peer's `MAX_STREAMS` limit), registers a raw-app receive slot so the stream
  participates in the existing reap-pin UAF guard and so the client's reply
  bytes reassemble into it, and returns the stream id. The embedder drives it
  with the existing `sendRawStreamData` (pending-send queueing, flow control,
  and loss retransmit are all stream-id-agnostic and reused unchanged). The
  client already accepts inbound server-initiated bidi STREAM frames as raw-app
  streams (`raw_app_recv` slots keyed by stream id). Prerequisite for
  zig-libp2p#214 (publish gossipsub `/meshsub` frames over the inbound
  connection). Covered by two loopback end-to-end tests: in-order multi-frame
  delivery + clean FIN/teardown, and a dropped-packet retransmit.

## [v1.7.33] - 2026-06-15

### Fixed

- **Raise the minimum congestion window 2 → 10 MSS to stop spurious-loss cwnd
  collapse.** Live zeam↔zeam diagnosis (the v1.7.32 CC line) showed cwnd pinned
  at exactly 2·MSS with `cong_events=10` while flow control was wide open
  (`fc_sent` ≪ `fc_max`) — i.e. a burst of spurious time-threshold/reordering
  losses on a sub-millisecond localhost path (`min_rtt_ms=0`) halved cwnd down
  to the 2·MSS floor and pinned it there, throttling the single persistent
  /meshsub gossip stream into permanent backpressure → outbox cap →
  `markPersistentGossipBroken` closes the connection → peers drop → node
  isolates. A 10·MSS floor (NewReno + Cubic) keeps cwnd usable through
  reordering noise without increasing bursting (sends remain bounded by the live
  cwnd). The v1.7.30 once-per-ACK `onLoss` fix stands; this addresses the
  residual collapse from genuinely-distinct (mostly spurious) loss events.

## [v1.7.32] - 2026-06-15

### Changed

- **Complete the backpressure diagnostic line.** The `queue full` warning now
  also carries `fc_sent / fc_max / stream_lim`, so one log line distinguishes
  congestion-blocked (`cwnd` small / `cong_events` climbing) from
  connection-flow-control-blocked (`fc_sent` ≈ `fc_max`) from
  per-stream-flow-control-blocked (`fc_sent` ≈ `stream_lim`) from a send-logic
  stall (cwnd large, fc open). Supersedes v1.7.31.

## [v1.7.31] - 2026-06-15

### Changed

- **Surface congestion state on the `queue full` backpressure warning** (and
  promote the CC trace to `warn`). Embedders (zeam) filter zquic `info` logs, so
  the v1.7.30 CC trace was invisible. The visible `pending-stream-send queue
  full` warning now carries `cwnd / ssthresh / state / bif / cong_events /
  acked / srtt / min_rtt / latest_rtt`, so a still-wedged stream's congestion
  state is diagnosable without enabling debug logging.

## [v1.7.30] - 2026-06-15

### Fixed

- **Congestion window collapse on multi-packet loss.** Both the client and
  server loss arms called `cc.onLoss(lp.pn)` **once per lost packet** inside the
  `lost_buf` loop. `onLoss` halves cwnd whenever `pn > end_of_recovery`, and
  `lost_buf` PNs arrive in arbitrary (swap-removed) order — so a single
  multi-packet loss event halved cwnd repeatedly (cwnd → cwnd/2ⁿ), pinning the
  window tiny (~15 MSS observed) and starving the persistent `/meshsub` gossip
  stream into permanent backpressure (queue-full + sync lag on zeam↔lantern).
  Now `cc.onLoss` is called **once per ACK** with `OnAckResult.largest_lost_pn`,
  as RFC 9002 §7.3.2 intends (one reduction per loss event).

### Changed

- **Initial congestion window raised 10 → 32 MSS** (NewReno + Cubic; RFC 9002
  §7.2 permits a larger IW), giving bursty single-stream gossip headroom before
  ACK-clocking dominates.
- **Per-stream pending-send caps raised** to 4096 entries / 32 MiB (from 1024 /
  8 MiB) to absorb transient bursts without cratering into backpressure.

### Added

- **Backpressure CC trace** (`info`): on a drain stall, log
  `cwnd / ssthresh / state / bif / cong_events / acked / srtt / min_rtt /
  latest_rtt` so a cwnd pinned by losses (`cong_events` climbing) is
  distinguishable from ACK-clock starvation (`acked` flat).

## [v1.7.29] - 2026-06-15

### Fixed

- **Never queue a zero-length (FIN-only) frame in `pending_stream_sends`.** The
  v1.7.28 FIN-only retransmit, when the re-send was congestion-blocked (exactly
  the heavy-backpressure case), routed empty data through
  `enqueuePendingStreamSend` → `dupe(u8, &.{})`, storing the allocator's
  zero-length sentinel slice (`ptr=0xffff…`) in the pending queue. The drain
  path later freed that sentinel **directly** (`allocator.free`, bypassing the
  v1.7.26 onAck guard), corrupting the drive thread's jemalloc tcache — which
  surfaced as a `Segmentation fault at 0x0` in an unrelated later allocation
  (observed in zig-libp2p `drainGossipsubOutbox` on zeam↔lantern under gossip
  backpressure). Both `enqueuePendingStreamSend` and
  `enqueuePendingStreamSendOwned` now reject zero-length frames at the source.

## [v1.7.28] - 2026-06-14

### Fixed

- **Retransmit lost FIN-only STREAM frames.** v1.7.27 stopped tracking a
  retransmit buffer for empty (FIN-only) frames to avoid the zero-length
  sentinel free — but that also dropped FIN retransmission entirely: a lost
  stream-close FIN was never re-sent, leaving the peer's stream half-open and
  hanging req/resp until timeout (observed as sync lag on zeam↔lantern). The
  client and server loss arms now re-send a bare FIN (empty STREAM frame, no
  buffer) when a FIN-only packet is declared lost, and the server send path
  marks FIN-only packets so the loss arm surfaces them.

### Changed

- **Demote the `refusing to free corrupt stream_data` guard log from `warn` to
  `debug`.** With the v1.7.27 root-cause fix in place the guard should never
  fire in normal operation; keep it quiet as pure defense-in-depth.

## [v1.7.27] - 2026-06-14

### Fixed

- **Root cause of the loss-detector free crash: never create a retransmit
  buffer for zero-length (FIN-only) STREAM frames.** Every libp2p stream close
  sends `sendRawStreamData(.., &[_]u8{}, true)`. The client and server send
  paths duped that empty slice into a retransmit buffer; `dupe(u8, &.{})`
  returns the allocator's zero-length sentinel slice (`ptr=0xffff…`, `len=0`).
  Tracking it in a `SentPacket` and freeing it on ack/loss handed jemalloc a
  bogus pointer → `Segmentation fault at 0x0` in `arena_dalloc_large`. Confirmed
  live: the v1.7.26 guard logged every corrupt free as exactly
  `ptr=0xffffffffffffffff len=0`. Both `Client.clientSendRawStreamFrame` and
  `Server.sendRawStreamDataInner` now carry empty STREAM frames with no
  retransmit buffer (`stream_data = null`). The `freeStreamDataChecked` guard
  from v1.7.26 is retained as defense-in-depth. This also supersedes the earlier
  server-side `edata_list_inactive_remove` alias band-aid (same root cause: two
  empty dupes shared the sentinel pointer).

## [v1.7.26] - 2026-06-14

### Fixed

- **Loss detector: guard `stream_data` retransmit-buffer frees against corrupt
  descriptors.** Under heavy gossip send load a `SentPacket` could reach
  `onAck`'s free path with a garbage `stream_data` slice (zero / absurd
  length), segfaulting deep in jemalloc (`arena_dalloc_large`, address `0x0`)
  and taking down the embedding node (seen on zeam↔lantern devnets). The loss
  detector's own ownership logic is proven correct (200k-iteration adversarial
  fuzz of the `onPacketSent → onAck → lost_buf transfer → retransmit` protocol
  under the testing allocator), so the corruption arrives from outside it.
  `freeStreamDataChecked` now validates the slice length before freeing: a
  suspect descriptor is logged with `pn / stream_id / ptr / len` and the free is
  skipped (leaks ≤ one small buffer) rather than crashing the process. This is a
  survivable mitigation + diagnostic, not a root-cause fix.

### Changed

- **Demote the `pending-stream-send drain stalled` log from `warn` to `debug`**
  — it is expected backpressure under flow-control / congestion limits and was
  noisy on busy connections.

## [v1.7.6] - 2026-06-12

### Fixed

- **Drain deferred STREAM bytes every `processPendingWork` tick** on server
  and client (before PTO), matching quinn `poll_transmit` prioritization of
  queued app data over keepalive probes.
- **Rate-limited stall logging** when `pending_stream_sends` cannot drain
  (reports CC / pacer / loss-detector block reason and queue depth).
- **Client drain / send** no longer puts untracked STREAM packets on the wire
  when the loss-detector ring is full — entries are re-queued instead.

## [v1.7.5] - 2026-06-12

### Fixed

- **Align raw STREAM send scheduling with quinn `poll_transmit`.** Server
  raw-stream sends and pending-queue drains now gate on congestion window,
  pacer, and loss-detector capacity (previously server bypassed CC). Client
  and server no longer put untracked packets on the wire when the loss
  detector is full — bytes are deferred to `pending_stream_sends` instead.
- **Client loss retransmit CC parity.** CC-blocked client retransmits enqueue
  to `pending_stream_sends` (mirroring server `http09_rtx` pacing) instead of
  blasting past cwnd.

## [v1.7.4] - 2026-06-12

### Fixed

- **Coalesce contiguous pending STREAM bytes on enqueue.** Gossipsub's
  sequential 1200-byte chunks on `/meshsub` no longer consume one of the
  1024 pending-queue slots each time CC blocks — they append to the tail
  entry instead, preventing the ~30s queue-full wedge and the follow-on
  quinn `decryption failed` burst when the backlog drained as many tiny
  frames at once.
- **Drain pending STREAM bytes before fresh client sends and before
  enqueueing on CC block**, looping until stalled so CC window openings
  empty the backlog before new entries are added.

## [v1.7.3] - 2026-06-12

### Fixed

- **Pending STREAM queue backpressure without redial thrashing.** When the
  per-connection `pending_stream_sends` cap is hit, return backpressure to
  the embedder instead of marking the connection draining (which caused a
  zeam→quinn redial/log storm). Deduplicate enqueue by `(stream_id, offset)`
  so embedder retries do not multiply queue entries. Drain deferred bytes
  before enqueue and run `Client.checkPto` from `processPendingWork` so
  CC-blocked gossip can drain while the recv loop is idle.

## [v1.7.2] - 2026-06-11

### Fixed

- **Client raw STREAM sends now honor congestion control and return accepted
  byte count.** Fresh `Client.sendRawStreamData` calls gate on `cc.canSend()`
  and the pacer (matching the server path) and enqueue to
  `pending_stream_sends` when blocked instead of blasting past the window.
  The function now returns how many payload bytes were accepted (0 on reject)
  so embedders like zig-libp2p do not advance `send_offset` when zquic did
  not take the bytes — eliminating permanent STREAM offset holes that caused
  quinn peers to stop decrypting gossip after ~25s. Added `sendClient1Rtt`
  helper so PING, DATA_BLOCKED, and PLPMTU probes update LD+CC like
  `Server.send1Rtt`.

---

## [v1.7.0] - 2026-06-11

### Fixed

- **Stop silently dropping flow-control-blocked raw STREAM bytes (RFC 9000
  §4, §19.9, §19.13).** When the peer's per-stream (`peer_initial_max_stream_data_*`
  / MAX_STREAM_DATA) or connection-level (`peer_initial_max_data` / MAX_DATA)
  receive window was exhausted, both `Server.sendRawStreamData` and
  `Client.sendRawStreamData` used to emit a STREAM_DATA_BLOCKED / DATA_BLOCKED
  frame and then **silently discard the application's bytes**. The embedder
  has no return value to inspect and the writer adapter advances its own
  `send_offset` unconditionally, so any flow-control hit left a permanent
  hole in the QUIC stream: the receiver could not parse messages past
  that gap, never read the bytes, never issued MAX_STREAM_DATA, and the
  connection eventually idle-closed with `reason=error`. This was the
  root cause of the zeam ↔ ethlambda gossipsub wedge described in the
  zig-libp2p v0.1.43 changelog. The previous fixes (zquic v1.6.17
  keepalive PINGs, v1.6.18 connection-lost detection, zig-libp2p
  v0.1.43 app-layer gossip keepalive) all addressed downstream
  symptoms of the silent drop.

  Each `ConnState` now owns a `pending_stream_sends` queue (capped at
  1024 entries / 8 MB per connection). On gate failure the bytes are
  duplicated onto the heap and enqueued instead of dropped, and the
  STREAM_DATA_BLOCKED / DATA_BLOCKED frame is still emitted so the peer
  knows to issue credit. `Server.drainPendingStreamSends` /
  `Client.drainPendingStreamSends` walk the queue and put entries on
  the wire whenever credit allows; ownership of the buffer transfers
  into the loss detector so the bytes are retransmittable. Drain is
  invoked from the MAX_DATA / MAX_STREAM_DATA frame handlers and as a
  safety net on every `checkPto` tick. On queue overflow the connection
  is marked `draining` so the embedder reconnects rather than punching
  a hole in the stream.

  Three new unit tests pin the enqueue ordering, the per-entry cap, and
  the per-byte cap.

---

## [v1.6.18] - 2026-06-11

### Fixed

- **Connection-lost declaration when CONNECTION_CLOSE is dropped (RFC 9002 §6.2,
  RFC 9000 §10.2).** v1.6.17's keepalive PING refreshes the peer's idle timer
  while ACKs flow, but offers no recovery when the path itself fails:
  if every probe and keepalive is dropped (kernel UDP buffer overflow, NAT
  rebind, peer crash) the `draining` flag only ever flips on receipt of a
  CONNECTION_CLOSE frame — which by definition cannot arrive in those
  conditions. Result: zig-libp2p's `detectOutboundConnectionClose` never
  fires, the dead slot lingers, and the application keeps publishing into
  the void. `checkPto` now adds a third branch on both `Server` and
  `Client`: if the peer has not ACK'd anything for `2 ×
  effective_max_idle_timeout` (60 s with the 30 s default), the connection
  is declared lost — `draining = true` is set and the standard `3 × PTO`
  draining deadline is armed so the application layer can evict and redial.

---

## [v1.6.17] - 2026-06-11

### Fixed

- **Idle-timeout keepalive PINGs (RFC 9000 §10.1.2).** `checkPto` only sent
  PING probes when `bytes_in_flight > 0`. When the application was quiet or
  receive-only (e.g. zeam's gossipsub QUIC connection while ethlambda is the
  busy publisher between zeam slots), no ACK-eliciting packet went out for
  the full `peer_max_idle_timeout` window, so the peer's idle timer expired
  silently and rust-libp2p / quic-go closed the connection with an
  error-class reason. Now both `Server.checkPto` and `Client.checkPto` emit a
  PING every `min(local, peer) max_idle_timeout / 2` independently of
  `bytes_in_flight`. PTO and keepalive use separate bookkeeping
  (`last_pto_ms` vs new `last_keepalive_ms`) so a keepalive does not poison
  PTO backoff.

---

## [v1.6.15] - 2026-06-08

### Fixed

- **Client Handshake CRYPTO reassembly.** Quinn/rust-libp2p (ethlambda) split
  the server flight across multiple Handshake CRYPTO frames at non-zero offsets.
  The client previously called `processServerFlight` on each chunk in isolation,
  so EncryptedExtensions/Certificate/Finished never assembled and outbound
  zquic → quinn dials stalled. Chunks are now accumulated in offset order
  (with the existing reorder buffer) before parsing the full flight.

---

## [v1.6.14] - 2026-06-08

### Fixed

- **Server Initial ClientHello retransmit replay.** When a client retransmits
  its Initial ClientHello after the server has already progressed, the server
  now replays the stored server flight instead of failing the handshake.

---

### Fixed

- **Ignore `RETIRE_CONNECTION_ID` sequence 0 from quic-go.** RFC 9000 §5.1.2
  forbids retiring the initial CID, but quic-go (go-libp2p) sometimes sends it
  after Identify on a new stream. Previously zquic closed with
  `PROTOCOL_VIOLATION`, breaking go-libp2p client → zquic server ping interop.
  The frame is now dropped on both server and client receive paths.

---

## [v1.6.11] - 2026-06-08

### Fixed

- **TLS `CertificateRequest` `signature_algorithms` wire format.** The inner
  `SignatureSchemeList` length prefix was missing in `buildCertificateRequest`,
  causing compliant TLS parsers (go-libp2p, rust-libp2p) to reject the request
  and block cross-impl mutual-TLS dials.

---

## [v1.6.10] - 2026-06-08

### Fixed

- **`Client.initInPlace` / `initFromSocketInPlace`.** New in-place initializers for
  heap-allocated clients (avoids a stack-sized return copy in downstream users
  like zig-libp2p).  Zero the output struct before populating fields so
  `initial_pkt_len` and similar state is not left undefined.

### Added

- **`Client.initInPlace` and `Client.initFromSocketInPlace`.** Write connection
  state directly into caller-owned storage; `init` / `initFromSocket` delegate
  to these helpers.

---

## [v1.6.9] - 2026-06-08

### Fixed

- **`Client.init` compile error in v1.6.8.** Partial struct literals must
  include `.conn = .{}` before `configureNewConn` fills the field.

---

## [v1.6.8] - 2026-06-08

### Fixed

- **`Client.init` stack overflow.** The enlarged `ConnState` (http/0.9 server
  arrays from v1.6.7) made `Client.init` stack-allocate two copies transiently
  (`var conn` plus the returned `Client`), overflowing default test-thread stacks
  in downstream consumers such as zig-libp2p.  Connection state is now
  configured in-place via `Client.configureNewConn`.

---

## [v1.6.7] - 2026-06-08

### Fixed

- **quinn→zquic HTTP/0.9 multiplexing interop.** Pace and congestion-control-gate
  every http/0.9 data send (immediate path, pending drain, active slots, FIN and
  loss retransmits) so quinn's ~2000-stream burst is not answered as one blast
  that overruns the NS3 bottleneck queue. Defer cwnd-blocked loss retransmits
  into a bounded `http09_rtx` queue. Only count 1-RTT packets toward
  `bytes_in_flight` when the loss detector tracks them (prevents a permanent
  PTO PING loop when the LD ring fills). Stop re-entering `drainHttp09Pending`
  from send helpers — that swap-remove corruption silently dropped queued
  requests (~17 streams with no server response).

- **Cross-impl quinn interop (handshake, transfer, download).** ALPN echo for
  arbitrary client preferences, QUIC transport-parameter extension type echo,
  coalesced Initial/Handshake receive resync, client stream reordering, and
  proactive MAX_STREAMS for quinn's stream credit model.

- **Packet number guard.** `decompressPacketNumber` no longer over/underflows
  on extreme PN gaps (#161).

### Added

- **Issue #138 P1 transport parity.** DPLPMTUD probes (`PlPmtuState`), preferred
  address TP encode, automatic key update after 1M 1-RTT packets, cipher-aware
  0-RTT for non-AES-128, ECN on Initial/Handshake, and `MigrationManager`
  wiring (anti-amplification, path challenge/response).

- **`raw_app_stream.zig`.** Extracted raw application stream send/receive path
  from `io.zig` for clearer ownership of retransmit buffers.

### Changed

- **HTTP/0.9 server scheduling.** Quinn-style immediate single-chunk responses,
  bounded pending/retransmit queues, and paced flush under congestion control.

---

## [v1.6.6] - 2026-06-03

### Added

- **In-memory PEM TLS config.** `ServerConfig` gains optional `cert_pem` /
  `key_pem` fields and `ClientConfig` gains `client_cert_pem` /
  `client_key_pem`. When set, the cert and key are parsed straight from
  caller-owned PEM bytes — the filesystem is never touched. The
  path-based fields (`cert_path`, `key_path`, `client_cert_path`,
  `client_key_path`) remain the fallback; if both are supplied, the PEM
  fields win. The byte-level parsers `parseCertDerFromPem` and
  `parsePrivateKeyFromPem` are also exposed for direct use. This lets
  higher-level libraries (zig-libp2p, …) hand zquic certs they minted in
  memory without writing them to disk first — fixes the `FROM scratch`
  container case where `/tmp` does not exist.

---

## [v1.6.5] - 2026-05-10

### Changed

- **Varint codec extracted to shared module.** `src/varint.zig` is now a thin
  re-export of [`zig-varint`](https://github.com/ch4r10t33r/zig-varint) `quic`
  submodule (v0.1.0). Wire format, public API (`encode`, `decode`,
  `encodedLen`, `lenToUsize`, `Reader`, `Writer`, `EncodeError`,
  `DecodeError`, `max_value`) and behavior are byte-identical with the
  previous in-tree implementation. Lets `zig-libp2p`, `zig-discv5`, and
  `zig-ethp2p` share a single canonical RFC 9000 §16 varint without
  drift.

### CI

- **Bumped quic-interop-runner per-test timeout from 60 s to 180 s.**
  GitHub-hosted runners have ~2-3× performance variance between
  allocations; the same SHA could pass in 27 s on one runner and time
  out at 60 s on another. The workflow now patches
  `TestCase.timeout()` to 180 s before invoking `run.py`, giving a 3×
  safety margin.

---

## [v1.6.3] - 2026-05-09

### Added

- **Mutual TLS 1.3 on QUIC (client certificate flight).** When `ClientConfig.client_cert_path` and
  `client_key_path` are both non-empty, the client sends `Certificate` + `CertificateVerify` + `Finished`
  after the server flight. The server verifies the client `CertificateVerify` and optional `Finished`-only
  clients remain supported.
- **`transport.io.serverConnPeerLeafCertificateDer`** — read the captured client leaf DER from a server
  `ConnState` after handshake completion when mutual TLS was used.

### Changed

- **`ServerHandshake.processClientHandshakeInbound`** replaces Finished-only handling in the QUIC server
  CRYPTO path (`handleHandshakeCrypto`).
- **Client handshake tail retransmit** may send multiple Handshake packets (chunked CRYPTO) when the
  mutual TLS payload exceeds one datagram.

---

## [v1.6.2] - 2026-05-09

### Added

- **`Client.peerLeafCertificateDer()`** — exposes the server's leaf
  certificate as DER bytes after handshake completion (PR #122).
  Embedders (e.g. a Zig libp2p PeerId derivation layer) can read the
  raw cert without re-parsing the TLS handshake. Lifetime is the
  client's; copy if you need it past `deinit`.

### Changed

- **TLS client leaf-cert capture.** `ClientHandshake.processServerFlight`
  now parses the first DER-encoded certificate from the TLS 1.3
  `Certificate` handshake message and stores up to 16 KiB on the client
  state. Existing handshake behaviour is unchanged.

---

## [v1.6.1] - 2026-05-09

### Fixed

- **Raw application STREAM reassembly.** Embedders using
  `raw_application_streams = true` previously dropped any STREAM frame that
  arrived ahead of the current contiguous offset (logged as `raw app gap`),
  losing data on UDP reordering. The receive path now buffers out-of-order
  chunks and splices them in once the preceding bytes arrive, matching the
  in-order reassembly the HTTP/0.9 and HTTP/3 code paths already had.
  Affects both server and client.

### Changed

- **`Client.flushDeferredAck` is now `pub`.** External event loops that drive
  the client via `feedPacket` (instead of the built-in `run` loop) must call
  `flushDeferredAck` once per inbound-drain cycle so the peer receives ACKs
  and keeps sending application data. Backwards-compatible: the built-in
  `run` loop already invokes it internally.

---

## [v1.6.0] - 2026-05-08

### Changed

- **Minimum Zig version: 0.15.0 → 0.16.0.** zig 0.16 reorganised most of
  `std`: `std.net`, much of `std.fs`, the high-level socket helpers in
  `std.posix`, `std.crypto.random`, and `std.time.milliTimestamp` were
  removed or relocated behind the new `std.Io` abstraction. zquic owns
  its own UDP event loop and does not need `std.Io`'s async machinery,
  so this release introduces `src/compat.zig` — a thin shim that
  reinstates the pre-0.16 surface (Address, fs.File, socket / bind /
  sendto / recvfrom / close, getAddressList, milliTimestamp, an
  OS-CSPRNG-backed `std.Random`) by dispatching directly to the platform
  syscall layer.
- **Pure-Zig restored.** `compat.zig` calls `std.os.linux.*` raw
  syscalls on Linux; the build links no libc on Linux, so
  `zig-out/bin/server` is a statically-linked ELF with zero C
  dependencies. Apple targets (macOS / iOS / tvOS / watchOS / visionOS)
  link Apple's `libSystem` because Darwin does not expose a stable
  syscall ABI — every other QUIC implementation does the same. The Zig
  source contains no third-party C dependencies on either platform.
- **Pure-Zig DNS resolver.** `getAddressList` parses IP literals first,
  then `/etc/hosts`, falling through to `getaddrinfo` only on Darwin.
  Linux without libc never calls libc DNS code.
- **`std.process.argsAlloc` → `std.process.Args.Iterator`.**
  `cmd/server` and `cmd/client` now take `std.process.Init.Minimal`.
- **`std.heap.GeneralPurposeAllocator` → `std.heap.DebugAllocator`.**
- **`X25519.KeyPair.generate()`** (now requires an `Io` instance) is
  replaced by `generateDeterministic(seed)` seeded from the compat
  CSPRNG.

### Fixed

- **Vendored `tls.zig` lifetime errors.** Four
  "returning address of expired local variable" failures in
  `vendor/tls/src/transcript.zig` (`pskBinder`,
  `serverFinishedTls13`, `clientFinishedTls13`, and the standalone
  `pskBinder_` helper) — now back the slices with scratch buffers on
  the inner Self struct.
- **`mmsghdr_const` alias removed in 0.16.** `transport/batch_io.zig`
  uses `mmsghdr` for both send and recv paths (identical layout).

### Limitations

- **`benchmarks/throughput_bench.zig` is stubbed** until
  `std.process.Child` (now Io-driven) is migrated. The bench-e2e CI
  step still runs (and exits 0) so the build chain stays green.
- **Vendored TLS** `Bundle.fromFilePath*` and `key_log.fileWrite` are
  stubbed out (`error.UnsupportedOnZig016`) — zquic does not consume
  them. Re-enable when porting to `std.Io.Dir`.
- **DPLPMTUD probing** still TODO (pre-existing).

### Tests

- 165/165 unit tests pass.
- 13/13 quic-interop-runner tests pass on the Linux pure-Zig build.

---

## [v1.5.0] - 2026-04-16

### Security

- **Retry token replay window closed (#108):** tokens now embed a minting
  timestamp and are rejected after 30 s. The `retry_secret` rotates hourly;
  the previous secret is kept for one TTL so tokens minted just before
  rotation remain valid. Bounds the blast radius of a leaked secret from
  "forever" to ~1 hour + 30 s.
- **Retry token format** extended from 53 to 61 bytes (adds 8-byte timestamp
  into the HMAC-SHA256 input).

### Fixed

- **FINAL_SIZE_ERROR enforcement (#109, RFC 9000 §3.5/§11.3):** per-connection
  tracker cross-checks RESET_STREAM `final_size` against any prior STREAM+FIN
  final size on the same stream, and vice-versa. Mismatch triggers
  `FINAL_SIZE_ERROR` (0x06) rather than silent acceptance.
- **Non-minimal varint rejection (#110, RFC 9000 §16 MUST):** `varint.decode`
  now rejects varints encoded in more bytes than needed. Prevents peers from
  bloating packets and restores canonicalization.
- **Active connection ID limit (#111, RFC 9000 §5.1.1):** client tracks the
  count of unretired CIDs received from the peer and drops packets that would
  exceed the advertised `active_connection_id_limit` (default 2 per §18.2).
- **ACK range underflow (#112, RFC 9000 §19.3):** `LossDetector.onAck` now
  returns `error.FrameEncodingError` when `first_ack_range > largest_acked`,
  and `AckFrame.parse` validates every additional gap/range for underflow.
  Previously saturating subtraction silently accepted malformed ACKs.
- **Stream-initiator violations (#113, RFC 9000 §19.8):** reject STREAM frames
  that write to send-only unidirectional streams (server rejects sid_type 3,
  client rejects sid_type 2). Bidirectional streams continue to accept frames
  in either direction.
- **Coalesced packet parser hardening (#115):** replaced raw `@intCast` of
  varint-decoded lengths with `varint.lenToUsize` for defense-in-depth.

### Changed

- **`varint.DecodeError`** adds `NonMinimalEncoding`.
- **`LossDetector.onAck`** now returns `OnAckError!OnAckResult` (breaking API
  vs 1.4.x).
- **`AckFrame.parse`** returns `(varint.DecodeError || error{FrameEncodingError})!…`.

### Documentation

- Prominently calls out that `MAX_CONNECTIONS = 16` on the demo `Server`
  struct is not a protocol cap; production embedders use `initFromSocket` +
  `feedPacket` with their own heap-allocated connection map (#114).

### Tests

- 165/165 unit tests pass (added 6 new tests: 5 varint boundary cases + 1 ACK
  underflow). 13/13 quic-interop-runner tests pass.

---

## [v1.4.0] - 2026-04-13

### Added

- **`transport/path_mtu.zig`:** clamp configured max UDP payload (RFC 9000 §14.1)
  and derive per-connection `app_stream_chunk` for HTTP/0.9 and HTTP/3 sends.
- **`ServerConfig` / `ClientConfig`:** optional `max_udp_payload`; **`ConnState`**
  fields `max_udp_payload` and `app_stream_chunk`.
- **`zquic.transport.path_mtu`** export in `root.zig`.

### Changed

- **`stream_manager.zig`:** explicit stream state transitions; **`onRecvReset`**
  and **`StreamManager.onResetStreamFrame`** for RESET_STREAM final-size rules.

### Fixed

- **HTTP/3 (`io.zig`):** use a comptime-sized buffer for DATA frame encoding so
  **ReleaseSafe** builds succeed (`conn.app_stream_chunk` is runtime-sized).

### Documentation

- README: configurable path MTU via `max_udp_payload`; DPLPMTUD probing still out
  of scope.

---

## [v1.3.0] - 2026-04-14

### Security

- **Timing-safe comparisons** for Retry HMAC verification, stateless reset token
  tails, and TLS Finished `verify_data` (`std.crypto.timing_safe.eql`).

### Changed

- **Peer stream limits (RFC 9000 §4.6):** track `peer_max_bidi_streams` /
  `peer_max_uni_streams`, apply incoming **MAX_STREAMS** frames on client and
  server, and enforce limits when allocating local stream IDs.
- **`rawAllocateNextLocalBidiStream` / `rawAllocateNextLocalUniStream`** now
  return `!u64` and **`error.StreamLimitExceeded`** when the peer’s limit is
  reached (breaking API vs 1.2.x).
- **Varint lengths:** `varint.lenToUsize` rejects values that do not fit in
  `usize`; STREAM, CRYPTO, NEW_TOKEN, and CONNECTION_CLOSE parsers use it.
- **Transport parameters:** `buildClientTransportParams` propagates varint
  encode errors instead of `catch unreachable`.
- **Constants:** single `types.max_datagram_size`, QUIC version literals via
  `types.Version`, shared TLS transport-params extension id, file-level
  `MAX_FIN_RETRANSMITS`.
- **Verbose I/O:** `std.log.scoped(.zquic)` instead of `std.debug.print` when
  verbose mode is enabled.

### Fixed

- **Streams (`stream_manager.zig`):** reject inconsistent FIN final sizes; ignore
  `closeLocal` when already closed or after `reset_sent`.
- **Version Negotiation `build`:** reject DCID/SCID lengths above 20 bytes.

### Documentation

- README: Path MTU discovery not implemented; embedder notes for `try`
  `rawAllocate*`.

---

## [v1.2.2] - 2026-04-13

### Security

- **Connection IDs and random material**: generate CIDs, stateless reset tokens,
  and PATH_CHALLENGE bytes with `std.crypto.random` instead of a millisecond-seeded
  PRNG (avoids collisions when multiple packets are handled in the same ms).

### Changed

- **QUIC-TLS transport parameters**: encode varints via `varint.encode` (remove
  duplicate local encoder).
- **Retry integrity verification**: always compute the expected tag before
  comparing; use `std.crypto.timing_safe.eql` for the 16-byte MAC.

### Documentation

- README “Implementation notes” (version negotiation, demo `Endpoint`, CSPRNG).
- Clarify demo `Endpoint` connection limit, `retry_token` buffer, version
  negotiation helpers, and `CachedAes128Context` design tradeoff.

---

## [v1.2.1] - 2026-04-12

### Added

- **`Client.startHandshake`**: send the Initial (ClientHello) when using an external UDP
  recv loop (`feedPacket` / `processPendingWork`) instead of `Client.run()`.

---

## [v1.2.0] - 2026-04-12

### Added

- **Custom ALPN**: `ServerConfig.alpn` / `ClientConfig.alpn` and helpers
  `serverTlsAlpn` / `clientTlsAlpn` for non-HTTP TLS handshakes
- **Raw application streams**: when `raw_application_streams` is enabled on both
  sides, inbound STREAM data is stored in `RawAppStreamSlot` buffers without
  HTTP/0.9 or HTTP/3 parsing
- **Embedder I/O**: `feedPacket` / `processPendingWork`, `initFromSocket` with
  optional socket ownership, local stream ID allocation, `sendRawStreamData` for
  1-RTT STREAM frames, and receive buffer views for raw streams
- **README**: Embedder guide section (consolidated from the former `docs/EMBEDDER.md`)

---

## [v1.1.0] - 2026-04-12

### Performance

- **Cached AES-128 key schedules**: pre-expand AES round keys in `KeyMaterial`,
  eliminating per-packet key schedule computation for both AEAD and header
  protection — ~36% throughput improvement on small transfers
- **Batch UDP receive**: use `recvmmsg` on Linux to receive up to 64 packets per
  syscall, reducing kernel transitions
- **Eliminated buffer copies**: build 1-RTT packets directly in the send buffer
  instead of copying through an intermediate buffer
- **Tuned congestion MSS**: raise maximum segment size from 1200 to 1350 bytes,
  increasing payload efficiency while staying within the 1500-byte Ethernet MTU

### Fixed

- **Uninitialized AES contexts**: cached AES contexts are now properly initialized
  in all key derivation paths (handshake, application, key update, session
  resumption, 0-RTT) — fixes resumption, http3, zerortt, connectionmigration,
  and multiplexing interop tests
- **IP fragmentation on NS3 links**: reduce H09/H3 chunk sizes to 1350 bytes so
  total IP packets (UDP payload + 28-byte IP/UDP headers) stay within the
  1500-byte MTU — fixes ecn and rebind-port interop tests
- **Hard-coded chunk sizes in retransmit paths**: H3 retransmit and path migration
  code now uses the module-level chunk constants instead of stale literals

### Interop

- All 13/13 quic-interop-runner test cases passing

---

## [v0.1.0] - 2026-04-11

### Added

#### Protocol coverage
- **RFC 9000** — QUIC transport: connection establishment, packet processing,
  stream multiplexing, flow control, connection migration, path validation
- **RFC 9001** — QUIC-TLS: Initial/Handshake/1-RTT encryption, header protection,
  key updates (client-initiated and server-initiated), session tickets, 0-RTT
- **RFC 9002** — Loss detection and congestion control: New Reno (cwnd, ssthresh,
  slow start / congestion avoidance / recovery states), RTT estimation (SRTT,
  RTTVAR, PTO), packet-threshold loss detection — all wired into the event loop
- **RFC 9114** — HTTP/3: framing (DATA, HEADERS, SETTINGS, GOAWAY, PUSH_PROMISE,
  CANCEL_PUSH, MAX_PUSH_ID), control streams, trailing HEADERS, GOAWAY on shutdown
- **RFC 9204** — QPACK: static table, dynamic table insertions, encoder/decoder
  streams, Section Acknowledgements, blocked streams
- **RFC 9369** — QUIC v2: initial secrets, packet type bits, Retry integrity tag

#### Frame handling
- RESET_STREAM (0x04) and STOP_SENDING (0x05) — stream cancellation
- CONNECTION_CLOSE (0x1c/0x1d) with draining period (3 × PTO, RFC 9000 §10.2.2)
- RETIRE_CONNECTION_ID (0x19) — CID lifecycle management with fresh CID issuance
- STREAMS_BLOCKED (0x16/0x17) — responds with MAX_STREAMS
- MAX_DATA, MAX_STREAM_DATA, DATA_BLOCKED, STREAM_DATA_BLOCKED — flow control
- PATH_CHALLENGE / PATH_RESPONSE — path validation and connection migration
- NEW_CONNECTION_ID — alternative CIDs for migration
- ECN (ACK-ECN frames, ECT(0) marking on all outgoing packets)

#### Infrastructure
- Idle timeout: connections idle for >30 s are silently closed (RFC 9000 §10.1)
- Congestion controller and RTT estimator reset on path migration (RFC 9002 §9.4)
- Release CI workflow (`.github/workflows/release.yml`) triggered on `v*` tags:
  runs tests + fmt check, builds linux/amd64 binaries, creates GitHub Release
- QLog writer for structured connection traces
- Stateless Reset token generation and detection

#### Interop
- All 13 QUIC interop runner test cases passing:
  `handshake`, `transfer`, `retry`, `chacha20`, `keyupdate`, `v2`, `ecn`,
  `resumption`, `http3`, `zerortt`, `connectionmigration`, `multiplexing`,
  `rebind-port`

### Known limitations
- 0-RTT anti-replay: no server-side nonce cache (safe for idempotent file serving;
  see issue #75 for the roadmap item)
- Connection-level stream limits are advertised but not enforced on the receive side

---

[Unreleased]: https://github.com/ch4r10t33r/zquic/compare/v1.6.3...HEAD
[v1.6.3]: https://github.com/ch4r10t33r/zquic/compare/v1.6.2...v1.6.3
[v1.6.2]: https://github.com/ch4r10t33r/zquic/compare/v1.6.1...v1.6.2
[v1.6.1]: https://github.com/ch4r10t33r/zquic/compare/v1.6.0...v1.6.1
[v1.6.0]: https://github.com/ch4r10t33r/zquic/compare/v1.5.0...v1.6.0
[v1.5.0]: https://github.com/ch4r10t33r/zquic/compare/v1.4.0...v1.5.0
[v1.4.0]: https://github.com/ch4r10t33r/zquic/compare/v1.3.0...v1.4.0
[v1.3.0]: https://github.com/ch4r10t33r/zquic/compare/v1.2.2...v1.3.0
[v1.2.2]: https://github.com/ch4r10t33r/zquic/compare/v1.2.1...v1.2.2
[v1.2.1]: https://github.com/ch4r10t33r/zquic/compare/v1.2.0...v1.2.1
[v1.2.0]: https://github.com/ch4r10t33r/zquic/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/ch4r10t33r/zquic/compare/v0.1.0...v1.1.0
[v0.1.0]: https://github.com/ch4r10t33r/zquic/releases/tag/v0.1.0
