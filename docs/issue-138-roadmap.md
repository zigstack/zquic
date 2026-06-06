# Issue #138 — zquic vs quinn parity roadmap

Tracker for closing the gap between zquic and production-grade quinn usage
(especially zeam / libp2p embedders). Updated after #150–#159.

## Status snapshot

| Area | State |
|------|-------|
| zquic↔zquic interop (13 tests) | **12–13/13** in PR CI |
| zquic↔quinn cross-impl | **P0 subset** in PR CI (handshake, transfer, multiplexing, both directions); full matrix nightly |
| Raw application streams | Implemented; unit tests for reassembly; embed via `feedPacket` + `processPendingWork` |
| 0-RTT | AES-128 only; ChaCha20 / AES-256 resumption not wired |
| Cipher-aware 1-RTT | Send + receive (#157, #158) |
| Key update / CID / anti-amp | Cooldown, retirement, 3× rule (#159) |
| Preferred address | **Receive + auto-migrate** (#156); **emit** not done |
| DPLPMTUD | Not implemented |
| DATAGRAM extension | Not implemented |
| HTTP/3 push | Not implemented |
| BBR | Not implemented |

## P0 — zeam / libp2p blockers

These must be green before relying on zquic as the libp2p QUIC transport.

- [x] **Cross-impl CI (PR-gating)** — handshake + transfer + multiplexing,
  quinn→zquic and zquic→quinn; failures fail the job (this PR).
- [x] **Client CONNECTION_CLOSE** — mirror server `sendConnectionClose` on
  protocol violations (STREAM_STATE_ERROR, CONNECTION_ID_LIMIT,
  RETIRE_CONNECTION_ID seq 0) (this PR).
- [x] **Raw stream reassembly tests** — out-of-order / overlap coverage for
  `rawAppStreamReceiveFrame` (this PR).
- [ ] **Cross-impl green on P0 matrix** — keep nightly full matrix tracking
  regressions until PR subset is consistently green.
- [ ] **Embedder validation in zeam** — end-to-end libp2p over zquic with
  `raw_application_streams` on a multi-client devnet.

## P1 — next after P0

- [ ] **DPLPMTUD** (RFC 8899) — probe size, PLPMTU state, PMTUD black-hole recovery.
- [ ] **Preferred address emit** — advertise TP 0x0d when server has a stable
  preferred path (symmetric with #156 receive path).
- [ ] **Automatic key update** — initiate on packet/time threshold (today:
  peer-initiated + manual client trigger only).
- [ ] **0-RTT non-AES-128** — derive early keys for ChaCha20 / AES-256 from
  stored ticket cipher suite.
- [ ] **ECN beyond 1-RTT** — ECT marking on Initial / Handshake sends; validate
  against quinn interop ECN test.
- [ ] **Wire `MigrationManager`** — centralize path validation, anti-amp, and
  preferred-address policy instead of scattered checks in `io.zig`.

## P2 — later

- [ ] **DATAGRAM extension** (RFC 9221).
- [ ] **HTTP/3 server push**.
- [ ] **BBR** congestion control (today: NewReno only).
- [ ] **General-purpose stream API** — first-class bidi/uni open/accept outside
  HTTP-oriented `io.zig` paths.
- [ ] **Remove `interop-run` `continue-on-error`** once cross-impl P0 is stable.

## Recently merged (#150–#159)

| PR | Topic |
|----|-------|
| 150 | Parse / apply peer transport params |
| 151 | Per-stream FC + CID pool + §18.2 params |
| 152 | Per-stream send-side MAX_STREAM_DATA |
| 153 | Emit max_udp_payload_size + disable_active_migration |
| 154 | RFC 9002 loss-detection completeness |
| 155 | 0-RTT AEAD send-side audit |
| 156 | Auto-migrate on preferred_address |
| 157 | Cipher-aware 1-RTT send |
| 158 | Cipher-aware 1-RTT receive + AES-256 HP fix |
| 159 | Key-update cooldown, CID retirement, anti-amp enforcement |

## CI layout

| Workflow | Scope |
|----------|-------|
| `.github/workflows/ci.yml` | Unit tests + zquic↔zquic full suite + P0 cross-impl |
| `.github/workflows/interop-cross-impl.yml` | Nightly full quinn↔zquic matrix (all tests, both roles) |
