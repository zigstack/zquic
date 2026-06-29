//! QUIC loss detection and RTT estimation (RFC 9002).
//!
//! Implements:
//!   - RTT estimation (§5): smoothed RTT, RTT variance, min RTT
//!   - Loss detection (§6): ACK-based, timeout-based
//!   - Probe Timeout (PTO) (§6.2)

const std = @import("std");

const log = std.log.scoped(.zquic);

/// Upper bound on a sane `stream_data` retransmit buffer length.  No legitimate
/// QUIC STREAM-frame retransmit buffer approaches this: fresh sends carry at
/// most one application chunk (gossip blocks are a few MiB at the extreme) and
/// coalesced pending sends are capped well under one datagram.  A length above
/// this means the `SentPacket` we are about to free was read from memory that
/// is not a valid tracked packet (e.g. an uninitialized slot surfaced by a
/// `sent_count` that drifted out of range) — freeing its `stream_data` would
/// hand jemalloc a garbage pointer and segfault.  See `freeStreamDataChecked`.
const max_sane_stream_data_len: usize = 64 * 1024 * 1024;

/// Pure predicate: does `sd` look like a real, freeable retransmit buffer?  A
/// zero or absurd length is the signature of a corrupted/uninitialized
/// `SentPacket` (e.g. a slot surfaced by a `sent_count` that drifted out of
/// range).  Kept free of side effects so it is unit-testable without emitting
/// the warning that the wrapper does.
fn streamDataLooksFreeable(sd: []const u8) bool {
    return sd.len != 0 and sd.len <= max_sane_stream_data_len;
}

/// Free a `SentPacket.stream_data` retransmit buffer, but first sanity-check the
/// slice via `streamDataLooksFreeable`.  Rather than hand jemalloc a garbage
/// pointer and segfault, a failed check logs the offending descriptor (so the
/// corruption is diagnosable on the next occurrence) and skips the free.
/// Skipping leaks at most one small buffer — vastly preferable to taking down
/// the whole node.  Returns true when the buffer was actually freed.
fn freeStreamDataChecked(allocator: std.mem.Allocator, sd: []u8, pn: u64, stream_id: u64) bool {
    if (!streamDataLooksFreeable(sd)) {
        log.debug(
            "recovery: refusing to free corrupt stream_data: pn={} stream_id={} ptr=0x{x} len={} — skipping (suspected SentPacket corruption)",
            .{ pn, stream_id, @intFromPtr(sd.ptr), sd.len },
        );
        return false;
    }
    allocator.free(sd);
    return true;
}

/// Initial RTT estimate (333ms per RFC 9002 §6.2.2)
pub const initial_rtt_ms: u64 = 333;

/// Multiplier for the RTT smoothing (1/8 = RTTVAR weight per RFC 6298)
const k_rtt_alpha: f64 = 1.0 / 8.0;
const k_rtt_beta: f64 = 1.0 / 4.0;
/// Minimum time before a packet is considered lost (RFC 9002 §6.1.2)
const k_time_threshold_num: u64 = 9;
const k_time_threshold_den: u64 = 8;
/// Minimum packet threshold for loss detection (RFC 9002 §6.1.1)
const k_packet_threshold: u64 = 3;
/// Maximum ACK delay in ms (RFC 9002 §5.3)
const k_max_ack_delay_ms: u64 = 25;
/// Granularity timer resolution in ms
const k_granularity_ms: u64 = 1;
/// Maximum PTO backoff exponent (RFC 9002 §6.2.1; quinn uses 16).
pub const max_pto_backoff_exponent: u32 = 16;
/// Persistent congestion duration multiplier (RFC 9002 §7.6.1)
const k_persistent_congestion_threshold: u64 = 3;

/// RTT estimator for a QUIC connection.
pub const RttEstimator = struct {
    /// Smoothed RTT (ms).
    srtt_ms: f64 = @floatFromInt(initial_rtt_ms),
    /// RTT variance (ms).
    rttvar_ms: f64 = @floatFromInt(initial_rtt_ms / 2),
    /// Minimum RTT observed (ms).
    min_rtt_ms: u64 = std.math.maxInt(u64),
    /// Latest RTT sample (ms).
    latest_rtt_ms: u64 = 0,
    /// True once first measurement taken.
    first_rtt_sample: bool = false,

    /// Update RTT estimates with a new ACK sample.
    /// `ack_delay_ms` is the peer-reported ACK delay.
    pub fn update(self: *RttEstimator, latest_rtt_ms: u64, ack_delay_ms: u64) void {
        self.latest_rtt_ms = latest_rtt_ms;

        // Update min RTT
        if (latest_rtt_ms < self.min_rtt_ms) {
            self.min_rtt_ms = latest_rtt_ms;
        }

        // Adjust for ACK delay (capped at max_ack_delay and latest_rtt - min_rtt)
        const adjusted_ack_delay = @min(ack_delay_ms, k_max_ack_delay_ms);
        const adjusted_rtt: f64 = if (latest_rtt_ms > self.min_rtt_ms + adjusted_ack_delay)
            @floatFromInt(latest_rtt_ms - adjusted_ack_delay)
        else
            @floatFromInt(latest_rtt_ms);

        if (!self.first_rtt_sample) {
            self.srtt_ms = adjusted_rtt;
            self.rttvar_ms = adjusted_rtt / 2.0;
            self.first_rtt_sample = true;
        } else {
            // RTTVAR = (1 - β) * RTTVAR + β * |SRTT - RTT|
            const diff = @abs(self.srtt_ms - adjusted_rtt);
            self.rttvar_ms = (1.0 - k_rtt_beta) * self.rttvar_ms + k_rtt_beta * diff;
            // SRTT = (1 - α) * SRTT + α * RTT
            self.srtt_ms = (1.0 - k_rtt_alpha) * self.srtt_ms + k_rtt_alpha * adjusted_rtt;
        }
    }

    /// Probe Timeout (PTO) value in ms (RFC 9002 §6.2.1).
    pub fn pto_ms(self: *const RttEstimator, max_ack_delay: u64, pto_count: u32) u64 {
        const capped = @min(pto_count, max_pto_backoff_exponent);
        const base_pto: f64 = self.srtt_ms + @max(4.0 * self.rttvar_ms, @as(f64, @floatFromInt(k_granularity_ms)));
        const with_delay: f64 = base_pto + @as(f64, @floatFromInt(max_ack_delay));
        const scaled = with_delay * std.math.pow(f64, 2.0, @floatFromInt(capped));
        return @intFromFloat(scaled);
    }

    /// Time-threshold loss delay in ms (RFC 9002 §6.1.2):
    ///   loss_delay = kTimeThreshold * max(SRTT, latest_RTT), floored at kGranularity.
    /// Before any RTT sample exists we fall back to the initial RTT so the
    /// loss timer is still well-defined during the handshake.
    pub fn loss_delay_ms(self: *const RttEstimator) u64 {
        const srtt: u64 = if (self.first_rtt_sample) @intFromFloat(@max(self.srtt_ms, 0.0)) else initial_rtt_ms;
        const base = @max(srtt, self.latest_rtt_ms);
        const scaled = (base * k_time_threshold_num) / k_time_threshold_den;
        return @max(scaled, k_granularity_ms);
    }

    /// Persistent-congestion duration in ms (RFC 9002 §7.6.1):
    ///   pc_duration = (SRTT + 4*RTTVAR + max_ack_delay) * kPersistentCongestionThreshold.
    /// Like `loss_delay_ms`, this falls back to the initial RTT before any sample.
    pub fn persistent_congestion_duration_ms(self: *const RttEstimator, max_ack_delay: u64) u64 {
        const srtt: f64 = if (self.first_rtt_sample) self.srtt_ms else @floatFromInt(initial_rtt_ms);
        const rttvar: f64 = if (self.first_rtt_sample) self.rttvar_ms else @as(f64, @floatFromInt(initial_rtt_ms)) / 2.0;
        const base: f64 = srtt + @max(4.0 * rttvar, @as(f64, @floatFromInt(k_granularity_ms))) + @as(f64, @floatFromInt(max_ack_delay));
        return @intFromFloat(base * @as(f64, @floatFromInt(k_persistent_congestion_threshold)));
    }
};

/// QUIC packet number spaces (RFC 9000 §12.3).
pub const PacketNumberSpace = enum(u2) {
    initial,
    handshake,
    application,
};

pub const pn_space_count: usize = 3;

/// A record of a packet that has been sent but not yet acknowledged.
pub const SentPacket = struct {
    pn: u64,
    send_time_ms: u64,
    size: usize,
    ack_eliciting: bool,
    in_flight: bool,
    space: PacketNumberSpace = .application,
    /// Stream metadata for application-layer retransmission.
    /// When `has_stream_data` is true the packet carried a STREAM frame for
    /// the given stream starting at `stream_offset`.  The loss detector
    /// surfaces this in `lost_buf` so the sender can rewind and re-send.
    has_stream_data: bool = false,
    stream_id: u64 = 0,
    stream_offset: u64 = 0,
    /// Heap-owned plaintext bytes for the raw-application STREAM frame, kept
    /// so we can re-encrypt them under a fresh PN on loss.  `null` for the
    /// HTTP/0.9 and HTTP/3 paths — those rewind their own per-slot state from
    /// the underlying file on disk and don't need an in-memory copy.
    ///
    /// Ownership rules:
    ///   - allocated by the producer (raw-app `sendRawStreamData`) via the
    ///     same allocator passed to `LossDetector.deinit` / `onAck`;
    ///   - freed by `onAck` when the carrying packet is acknowledged;
    ///   - ownership transfers into `lost_buf` when the packet is declared
    ///     lost — the caller MUST either re-attach the slice to a new
    ///     `SentPacket` (via `onPacketSent`) or free it.
    stream_data: ?[]u8 = null,
    /// FIN flag accompanying `stream_data` (so retransmit preserves the bit).
    stream_fin: bool = false,
};

/// Disposition of one in-flight packet against an incoming ACK.
const AckDisp = enum { acked, lost, keep };

/// Accumulators threaded through `classifyAck` across both onAck passes.
const AckAccum = struct {
    bytes_acked: u64 = 0,
    lost_bytes: u64 = 0,
    lost_count: usize = 0,
    largest_lost_pn: ?u64 = null,
    rtt_updated: bool = false,
    earliest_acked_eliciting_send_time: ?u64 = null,
    earliest_lost_eliciting_send_time: ?u64 = null,
    latest_lost_eliciting_send_time: ?u64 = null,
};

/// Classify a single in-flight packet against an ACK and apply its accounting
/// (RTT sample for `largest_acked`, ack/loss byte tallies, persistent-congestion
/// timing bounds, `stream_data` ownership). Pure per-packet logic shared by the
/// front-pop fast path and the compaction fallback in `LossDetector.onAck` —
/// returns whether the packet was acked, declared lost, or kept. Side effects:
/// frees acked `stream_data`; transfers lost `stream_data` ownership into
/// `lost_buf` (nulling the slot). Mirrors the RFC 9002 §6.1 / §7.6 rules.
fn classifyAck(
    p: *SentPacket,
    space: PacketNumberSpace,
    smallest_acked: u64,
    largest_acked: u64,
    largest_advanced: bool,
    time_lost_before: u64,
    now_ms: u64,
    ack_delay_ms: u64,
    rtt: *RttEstimator,
    lost_buf: []SentPacket,
    allocator: std.mem.Allocator,
    acc: *AckAccum,
) AckDisp {
    if (p.space != space) return .keep;
    // RTT sample from the largest acked packet in this space (once per ACK).
    if (largest_advanced and p.pn == largest_acked and !acc.rtt_updated) {
        rtt.update(now_ms -| p.send_time_ms, ack_delay_ms);
        acc.rtt_updated = true;
    }
    // Definitively acked: within [smallest_acked .. largest_acked].
    if (p.pn >= smallest_acked and p.pn <= largest_acked) {
        acc.bytes_acked += p.size;
        if (p.ack_eliciting) {
            if (acc.earliest_acked_eliciting_send_time) |t| {
                if (p.send_time_ms < t) acc.earliest_acked_eliciting_send_time = p.send_time_ms;
            } else acc.earliest_acked_eliciting_send_time = p.send_time_ms;
        }
        if (p.stream_data) |sd| {
            _ = freeStreamDataChecked(allocator, sd, p.pn, p.stream_id);
            p.stream_data = null;
        }
        return .acked;
    }
    // Below the acked range — RFC 9002 §6.1 loss detection for true gaps:
    // packet threshold (k_packet_threshold later PNs acked) OR time threshold.
    const packet_threshold_lost = (p.pn < smallest_acked and largest_acked >= p.pn + k_packet_threshold);
    const time_threshold_lost = (p.pn < smallest_acked and p.send_time_ms <= time_lost_before);
    if (packet_threshold_lost or time_threshold_lost) {
        acc.lost_bytes += p.size;
        if (acc.largest_lost_pn) |lpn| {
            if (p.pn > lpn) acc.largest_lost_pn = p.pn;
        } else acc.largest_lost_pn = p.pn;
        if (p.ack_eliciting) {
            if (acc.earliest_lost_eliciting_send_time) |t| {
                if (p.send_time_ms < t) acc.earliest_lost_eliciting_send_time = p.send_time_ms;
            } else acc.earliest_lost_eliciting_send_time = p.send_time_ms;
            if (acc.latest_lost_eliciting_send_time) |t| {
                if (p.send_time_ms > t) acc.latest_lost_eliciting_send_time = p.send_time_ms;
            } else acc.latest_lost_eliciting_send_time = p.send_time_ms;
        }
        if (acc.lost_count < lost_buf.len) {
            lost_buf[acc.lost_count] = p.*;
            p.stream_data = null;
            acc.lost_count += 1;
        } else {
            if (p.stream_data) |sd| {
                _ = freeStreamDataChecked(allocator, sd, p.pn, p.stream_id);
                p.stream_data = null;
            }
        }
        return .lost;
    }
    return .keep;
}

/// Loss detection state for one packet number space.
pub const LossDetector = struct {
    /// High-BDP paths can hold thousands of in-flight packets. At 32768 slots a
    /// full 32 MB cwnd (≈27k MTU-sized packets) fits without ever hitting the
    /// in-flight tracking cap — i.e. without sending packets that loss detection
    /// cannot see (a loss-detection blind spot under high cwnd).
    /// `sent` is now a HEAP-allocated slice (see `init`/`deinit`), so raising
    /// this only grows heap memory (~+2 MB/conn at 64 B/SentPacket) and never
    /// the stack of on-stack LossDetector allocations — the constraint that
    /// previously pinned this at 16384 (#233).
    pub const max_tracked_packets: usize = 32_768;
    const max_tracked = max_tracked_packets;

    /// In-flight packets form a DEQUE inside `sent`: the logical packets are
    /// `sent[head .. head + sent_count]`, oldest (lowest pn per space) first.
    /// `onPacketSent` pushes to the back; `onAck` pops acked/lost packets off
    /// the FRONT (advancing `head`, O(acked)) and never touches the untouched
    /// higher-pn suffix. Every mutation (push-back, front-pop, the compaction
    /// fallback, `abandonSpace`) preserves send order, so within each PN space
    /// the packets stay ascending by pn — the invariant the front-pop relies on.
    /// This replaced an unsorted flat array + swap-remove whose onAck rescanned
    /// ALL in-flight packets (O(sent_count), up to the cap) on every ACK —
    /// the per-packet cost that saturated the single drive thread under a full
    /// 31-peer mesh (#184 / drive-loop stall).
    ///
    /// HEAP-allocated (#233): a length-`max_tracked` slice owned by this
    /// detector. The default `&.{}` is an empty placeholder so a `.{}`-built
    /// LossDetector is inert until `init` allocates the real backing; `deinit`
    /// frees it. The deque indexing below treats `sent` exactly as it treated
    /// the former inline array — `sent.len == max_tracked` once `init` ran.
    sent: []SentPacket = &.{},
    sent_count: usize = 0,
    /// Physical index of the deque front (logical packet 0). See `sent`.
    head: usize = 0,
    largest_acked: [pn_space_count]u64 = [_]u64{0} ** pn_space_count,
    loss_time_ms: [pn_space_count]?u64 = .{null} ** pn_space_count,
    /// Cumulative count of packets this detector has declared lost over the
    /// connection's lifetime (diagnostic). A high value at connection-lost time
    /// vs. a low one distinguishes a retransmit/loss storm from a healthy
    /// transfer that simply stalled (peer went silent with data in flight).
    total_declared_lost: u64 = 0,
    /// In-flight-tracking-cap warning throttle (see `onPacketSent`).
    last_cap_warn_ms: u64 = 0,
    cap_reached_total: u64 = 0,

    fn spaceIdx(space: PacketNumberSpace) usize {
        return @intFromEnum(space);
    }

    /// Allocate the heap-backed `sent` deque (length `max_tracked`). Every other
    /// field keeps its struct default. Callers must pair this with `deinit` so
    /// the slice is freed. The backing memory is `undefined` until written by
    /// `onPacketSent` — only `sent[head .. head + sent_count]` is ever read.
    pub fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!LossDetector {
        var self = LossDetector{};
        self.sent = try allocator.alloc(SentPacket, max_tracked);
        return self;
    }

    /// Clear the deque in place WITHOUT freeing the backing slice (RFC 9002 §9.4
    /// path-change reset). Frees any in-flight retransmit buffers first so the
    /// reset does not leak `stream_data`, then rewinds the deque and per-space
    /// state. The slice stays allocated and reusable.
    pub fn reset(self: *LossDetector, allocator: std.mem.Allocator) void {
        for (self.sent[self.head .. self.head + self.sent_count]) |*p| {
            if (p.stream_data) |sd| _ = freeStreamDataChecked(allocator, sd, p.pn, p.stream_id);
            p.stream_data = null;
        }
        self.sent_count = 0;
        self.head = 0;
        self.largest_acked = [_]u64{0} ** pn_space_count;
        self.loss_time_ms = .{null} ** pn_space_count;
    }

    /// True when this PN space still has ack-eliciting packets in flight.
    pub fn inflightInSpace(self: *const LossDetector, space: PacketNumberSpace) bool {
        for (self.sent[self.head .. self.head + self.sent_count]) |p| {
            if (p.space == space and p.ack_eliciting and p.in_flight) return true;
        }
        return false;
    }

    /// Pointer to the most-recently-sent (back-of-deque) tracked packet, or
    /// null when nothing is tracked. Callers attach stream metadata to the
    /// packet they just recorded via `onPacketSent`.
    pub fn lastSentPtr(self: *LossDetector) ?*SentPacket {
        if (self.sent_count == 0) return null;
        return &self.sent[self.head + self.sent_count - 1];
    }

    /// Stop tracking in-flight packets in a PN space (RFC 9001: Initial/Handshake
    /// keys are discarded once the handshake completes).
    pub fn abandonSpace(self: *LossDetector, space: PacketNumberSpace, allocator: std.mem.Allocator) void {
        // Order-preserving compaction (keeps the per-space pn ordering intact).
        const base = self.head;
        var w: usize = 0;
        var r: usize = 0;
        while (r < self.sent_count) : (r += 1) {
            const p = &self.sent[base + r];
            if (p.space == space) {
                if (p.stream_data) |sd| {
                    _ = freeStreamDataChecked(allocator, sd, p.pn, p.stream_id);
                    p.stream_data = null;
                }
                // drop — do not advance the write cursor
            } else {
                if (w != r) self.sent[base + w] = self.sent[base + r];
                w += 1;
            }
        }
        self.sent_count = w;
        const sidx = spaceIdx(space);
        self.largest_acked[sidx] = 0;
        self.loss_time_ms[sidx] = null;
    }

    /// Free any heap-owned retransmit buffers attached to in-flight packets AND
    /// the heap-backed `sent` slice itself (#233). Caller passes the same
    /// allocator used to `init` the detector and to populate `stream_data`.
    /// Idempotent: after this `sent` is the empty placeholder again, so a second
    /// call (or a call on a `.{}`-built detector that was never `init`ed) is a
    /// no-op.
    pub fn deinit(self: *LossDetector, allocator: std.mem.Allocator) void {
        for (self.sent[self.head .. self.head + self.sent_count]) |*p| {
            if (p.stream_data) |sd| _ = freeStreamDataChecked(allocator, sd, p.pn, p.stream_id);
            p.stream_data = null;
        }
        self.sent_count = 0;
        self.head = 0;
        if (self.sent.len != 0) {
            allocator.free(self.sent);
            self.sent = &.{};
        }
    }

    /// True when another in-flight packet can be tracked (quinn always
    /// records packets it puts on the wire; we gate sends the same way).
    pub fn hasCapacity(self: *const LossDetector) bool {
        return self.sent_count < max_tracked;
    }

    /// Record a newly sent packet.
    ///
    /// If `pkt.stream_data` is non-null and we cannot record the packet
    /// (buffer full), the caller is responsible for freeing the slice —
    /// otherwise it would leak.  Returns true when the packet was stored.
    pub fn onPacketSent(self: *LossDetector, pkt: SentPacket) bool {
        if (self.sent_count < max_tracked) {
            // Push to the back of the deque. If front-pops have walked `head`
            // to the end of the storage, slide the live window back to index 0
            // first — O(sent_count), amortized across `max_tracked` sends.
            if (self.head + self.sent_count >= max_tracked) {
                std.mem.copyForwards(
                    SentPacket,
                    self.sent[0..self.sent_count],
                    self.sent[self.head .. self.head + self.sent_count],
                );
                self.head = 0;
            }
            self.sent[self.head + self.sent_count] = pkt;
            self.sent_count += 1;
            return true;
        }
        // Rate-limit: at a 16384-deep cap a stalled conn hits this on EVERY
        // ack-eliciting send (hundreds/sec observed live: 44k logs/3min). Each
        // log.warn is a synchronous write on the QUIC drive thread, so the
        // logging itself becomes a drive-loop bottleneck that delays ACKs to
        // every other peer — feeding the very stall that fills the cap. Emit at
        // most ~once/5s per detector; count the rest.
        self.cap_reached_total += 1;
        if (pkt.send_time_ms -| self.last_cap_warn_ms >= 5000) {
            self.last_cap_warn_ms = pkt.send_time_ms;
            log.warn(
                "recovery: in-flight tracking cap ({d}) reached — packet pn={d} not tracked ({d} total, throttled 5s)",
                .{ max_tracked, pkt.pn, self.cap_reached_total },
            );
        }
        return false;
    }

    pub const OnAckError = error{FrameEncodingError};

    pub const OnAckResult = struct {
        lost_count: usize,
        rtt_updated: bool,
        bytes_acked: u64,
        lost_bytes: u64,
        /// True when the set of ack-eliciting packets declared lost by this
        /// ACK spans a duration ≥ `persistent_congestion_duration_ms`
        /// (RFC 9002 §7.6).  The caller should invoke
        /// `CongestionController.onPersistentCongestion` in that case.
        persistent_congestion: bool,
        /// Largest packet number declared lost by this ACK, if any.  Exposed
        /// so the caller can invoke `cc.onLoss(largest_lost_pn)` once per
        /// ACK instead of once per lost packet — the recovery period bound
        /// is what matters, not the individual PNs.
        largest_lost_pn: ?u64,
    };

    /// Process an ACK frame. Returns packets declared lost.
    /// `now_ms` is the current wall-clock time in milliseconds.
    /// `rtt` is the RTT estimator.
    ///
    /// Returns `error.FrameEncodingError` if `first_ack_range > largest_acked`
    /// (RFC 9000 §19.3: the first range must not underflow the packet number space).
    pub fn onAck(
        self: *LossDetector,
        space: PacketNumberSpace,
        largest_acked: u64,
        /// First ACK range from the ACK frame (RFC 9000 §19.3.1).
        /// The number of contiguous packets before `largest_acked` that are
        /// also acknowledged in the same range.  The smallest packet number
        /// confirmed acked by this range is `largest_acked - first_ack_range`.
        first_ack_range: u64,
        ack_delay_ms: u64,
        now_ms: u64,
        rtt: *RttEstimator,
        /// Caller-provided buffer.  On return the first `lost_count` entries
        /// hold the full SentPacket descriptors for packets declared lost.
        /// Callers that stored stream metadata in `has_stream_data` can use
        /// this to rewind and retransmit the affected data.  For lost
        /// packets whose `stream_data` is non-null, ownership of that slice
        /// transfers to the caller (see `SentPacket.stream_data` docs).
        lost_buf: []SentPacket,
        /// Allocator used to free `stream_data` for packets acked by this
        /// range.  Pass the same allocator that the producer used when
        /// attaching the data via `onPacketSent`.
        allocator: std.mem.Allocator,
    ) OnAckError!OnAckResult {
        // Validate: first_ack_range must not exceed largest_acked (RFC 9000 §19.3).
        // A saturating subtract would mask this protocol violation as a silent
        // accept of packets [0..largest_acked], so we reject here.
        if (first_ack_range > largest_acked) return error.FrameEncodingError;

        const sidx = spaceIdx(space);
        const largest_advanced = largest_acked > self.largest_acked[sidx];
        if (largest_advanced) self.largest_acked[sidx] = largest_acked;

        // The first ACK range covers [smallest_acked .. largest_acked].
        // Packets in this range are definitively acknowledged. Packets below
        // smallest_acked may be in a gap (possibly lost).
        const smallest_acked = largest_acked - first_ack_range;

        // Time-threshold loss bound, computed once (RFC 9002 §6.1.2). A packet
        // older than this is lost even if < k_packet_threshold later PNs acked.
        const loss_delay = rtt.loss_delay_ms();
        const time_lost_before = now_ms -| loss_delay;

        var acc: AckAccum = .{};

        // ---- Fast path: pop acked/lost packets off the deque FRONT. The deque
        // is send-ordered (ascending pn per space), so once a front packet of
        // THIS space has pn > largest_acked, every remaining packet of this
        // space does too — nothing more to process. O(acked + lost), and the
        // unacked higher-pn suffix (the bulk under load) is never scanned. This
        // is the whole point of the deque: at the 16384 in-flight cap the old
        // flat-array rescan was O(16384) per ACK and saturated the drive thread.
        var done_front = false;
        while (self.sent_count > 0) {
            const p = &self.sent[self.head];
            if (p.space != space) break; // other-space packet blocks the front
            if (p.pn > largest_acked) {
                done_front = true; // sorted ⇒ all remaining of this space are keeps
                break;
            }
            switch (classifyAck(p, space, smallest_acked, largest_acked, largest_advanced, time_lost_before, now_ms, ack_delay_ms, rtt, lost_buf, allocator, &acc)) {
                .acked, .lost => {
                    self.head += 1;
                    self.sent_count -= 1;
                },
                .keep => break, // gap-keeper (pn < smallest, not yet lost) — finish via compaction
            }
        }

        // ---- Fallback: order-preserving compaction over the remaining window.
        // Runs only when the front stalled on an other-space packet or a
        // gap-keeper (reordering / multi-space handshake) — rare on a healthy
        // path, and bounded by the remaining (not total) in-flight count.
        if (!done_front and self.sent_count > 0) {
            const base = self.head;
            var w: usize = 0;
            var r: usize = 0;
            while (r < self.sent_count) : (r += 1) {
                const p = &self.sent[base + r];
                if (classifyAck(p, space, smallest_acked, largest_acked, largest_advanced, time_lost_before, now_ms, ack_delay_ms, rtt, lost_buf, allocator, &acc) == .keep) {
                    if (w != r) self.sent[base + w] = self.sent[base + r];
                    w += 1;
                }
            }
            self.sent_count = w;
        }
        if (self.sent_count == 0) self.head = 0; // keep `head` small when idle

        // Persistent congestion (RFC 9002 §7.6.1): the duration between the
        // earliest and latest ack-eliciting packets declared lost spans the
        // persistent_congestion threshold.  We only declare PC if no
        // ack-eliciting packet was acked within that interval (otherwise the
        // path clearly delivered something and is not in persistent
        // congestion).  An RTT sample must exist — without one we cannot
        // compute a meaningful threshold (RFC 9002 §7.6.2).
        var pc = false;
        if (rtt.first_rtt_sample) {
            if (acc.earliest_lost_eliciting_send_time) |t0| {
                if (acc.latest_lost_eliciting_send_time) |t1| {
                    if (t1 > t0) {
                        const span = t1 - t0;
                        const pc_dur = rtt.persistent_congestion_duration_ms(k_max_ack_delay_ms);
                        if (span >= pc_dur) {
                            // Contiguity: no ack-eliciting packet acked by this
                            // ACK fell inside (t0, t1).  If one did, this ACK
                            // proves the path is delivering and PC does not
                            // apply.
                            const overlap = if (acc.earliest_acked_eliciting_send_time) |ea|
                                (ea > t0 and ea < t1)
                            else
                                false;
                            if (!overlap) pc = true;
                        }
                    }
                }
            }
        }

        self.total_declared_lost += acc.lost_count;
        return OnAckResult{
            .lost_count = acc.lost_count,
            .rtt_updated = acc.rtt_updated,
            .bytes_acked = acc.bytes_acked,
            .lost_bytes = acc.lost_bytes,
            .persistent_congestion = pc,
            .largest_lost_pn = acc.largest_lost_pn,
        };
    }
};

test "rtt: initial values" {
    const testing = std.testing;
    const rtt = RttEstimator{};
    try testing.expectEqual(@as(f64, @floatFromInt(initial_rtt_ms)), rtt.srtt_ms);
    try testing.expect(rtt.pto_ms(k_max_ack_delay_ms, 0) > 0);
}

test "rtt: single sample update" {
    const testing = std.testing;
    var rtt = RttEstimator{};
    rtt.update(100, 10);
    try testing.expect(rtt.srtt_ms < 333.0); // moves toward 100
    try testing.expect(rtt.min_rtt_ms == 100);
    try testing.expect(rtt.first_rtt_sample);
}

test "rtt: pto increases with backoff" {
    const testing = std.testing;
    var rtt = RttEstimator{};
    rtt.update(50, 0);
    const pto0 = rtt.pto_ms(0, 0);
    const pto1 = rtt.pto_ms(0, 1);
    const pto2 = rtt.pto_ms(0, 2);
    try testing.expect(pto1 >= pto0 * 2 - 1);
    try testing.expect(pto2 >= pto1 * 2 - 1);
}

test "loss: packet threshold detection" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};

    // Send packets 0..5
    var i: u64 = 0;
    while (i < 6) : (i += 1) {
        _ = ld.onPacketSent(.{
            .pn = i,
            .send_time_ms = 100 + i * 10,
            .size = 100,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    // ACK packet 5 only (first_ack_range=0 means only pn=5 is in the acked range).
    // Packets 0, 1, 2 are in a gap and should be detected as lost via
    // k_packet_threshold (5 >= 0+3, 1+3, 2+3).
    var lost_buf: [8]SentPacket = undefined;
    const result = try ld.onAck(.application, 5, 0, 0, 200, &rtt, &lost_buf, testing.allocator);
    try testing.expect(result.lost_count >= 2);
}

test "loss: rejects invalid first_ack_range > largest_acked" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};
    var lost_buf: [4]SentPacket = undefined;
    // largest_acked=5, first_ack_range=10 → would underflow.
    try testing.expectError(
        error.FrameEncodingError,
        ld.onAck(.application, 5, 10, 0, 200, &rtt, &lost_buf, testing.allocator),
    );
}

test "loss: time-threshold declares old packet lost when gap < k_packet_threshold" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};
    // Establish an RTT sample so loss_delay is bounded and deterministic.
    rtt.update(50, 0);
    const loss_delay = rtt.loss_delay_ms();

    // Send pn 0 at t=100 and pn 1 at t=200.  Only one later PN gets acked,
    // so packet-threshold (kPacketThreshold=3) will NOT trip on pn 0.
    _ = ld.onPacketSent(.{ .pn = 0, .send_time_ms = 100, .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 1, .send_time_ms = 200, .size = 100, .ack_eliciting = true, .in_flight = true });

    // Ack pn 1 at a time far enough past pn 0's send to trigger time-threshold.
    const now = 200 + loss_delay + 1;
    var lost_buf: [4]SentPacket = undefined;
    const r = try ld.onAck(.application, 1, 0, 0, now, &rtt, &lost_buf, testing.allocator);
    try testing.expectEqual(@as(usize, 1), r.lost_count);
    try testing.expectEqual(@as(u64, 0), lost_buf[0].pn);
    try testing.expect(r.largest_lost_pn != null);
    try testing.expectEqual(@as(u64, 0), r.largest_lost_pn.?);
}

test "loss: persistent congestion across spread-out losses" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};
    // Pin a small SRTT so the PC threshold is small and easy to exceed.
    rtt.update(10, 0);
    const pc_dur = rtt.persistent_congestion_duration_ms(k_max_ack_delay_ms);

    // Send 6 ack-eliciting packets spanning > pc_dur, then ack only pn 5.
    // pns 0..2 are declared lost via packet-threshold; we space them so the
    // span between earliest and latest ack-eliciting lost packet exceeds
    // pc_dur.
    const t0: u64 = 1_000;
    const t_last = t0 + pc_dur + 50; // bound for the latest lost pn

    _ = ld.onPacketSent(.{ .pn = 0, .send_time_ms = t0, .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 1, .send_time_ms = t0 + (pc_dur / 2), .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 2, .send_time_ms = t_last, .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 3, .send_time_ms = t_last + 10, .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 4, .send_time_ms = t_last + 20, .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 5, .send_time_ms = t_last + 30, .size = 100, .ack_eliciting = true, .in_flight = true });

    // Ack only pn 5 so packet-threshold trips on 0, 1, 2.  Use a `now`
    // large enough that time-threshold also fires on 3 and 4.
    const now = t_last + 30 + rtt.loss_delay_ms() + 1;
    var lost_buf: [16]SentPacket = undefined;
    const r = try ld.onAck(.application, 5, 0, 0, now, &rtt, &lost_buf, testing.allocator);
    try testing.expect(r.lost_count >= 3);
    try testing.expect(r.persistent_congestion);
}

test "loss: no persistent congestion when ack proves path is delivering" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};
    rtt.update(10, 0);
    const pc_dur = rtt.persistent_congestion_duration_ms(k_max_ack_delay_ms);

    // pn 0 sent very early, then pn 1 sent inside the PC window and acked
    // (proving delivery), then pn 2..5 surrounding so packet-threshold
    // declares pn 0 lost.  Span of lost ack-eliciting packets is just pn 0
    // alone, so PC must not fire — additionally the acked pn 1 falls within
    // the loss window if there were a second lost packet, also blocking PC.
    const t0: u64 = 1_000;

    _ = ld.onPacketSent(.{ .pn = 0, .send_time_ms = t0, .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 1, .send_time_ms = t0 + 5, .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 2, .send_time_ms = t0 + pc_dur + 10, .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 3, .send_time_ms = t0 + pc_dur + 11, .size = 100, .ack_eliciting = true, .in_flight = true });
    _ = ld.onPacketSent(.{ .pn = 4, .send_time_ms = t0 + pc_dur + 12, .size = 100, .ack_eliciting = true, .in_flight = true });

    // Ack pns 1..4 in one contiguous range.  pn 0 hits packet-threshold
    // (largest_acked=4 ≥ 0+3) but pn 1 was acked inside the same ACK, so
    // even if a second loss were present, PC would not apply.
    var lost_buf: [8]SentPacket = undefined;
    const r = try ld.onAck(.application, 4, 3, 0, t0 + pc_dur + 20, &rtt, &lost_buf, testing.allocator);
    try testing.expect(r.lost_count >= 1);
    try testing.expect(!r.persistent_congestion);
}

test "loss: persistent_congestion_duration falls back to initial RTT before first sample" {
    const testing = std.testing;
    const rtt = RttEstimator{};
    // Before any sample, threshold should equal pc_threshold *
    //   (initial_rtt + 4 * initial_rtt/2 + max_ack_delay)
    //   = 3 * (333 + 666 + 25) = 3072.
    const got = rtt.persistent_congestion_duration_ms(k_max_ack_delay_ms);
    try testing.expectEqual(@as(u64, 3 * (333 + 666 + 25)), got);
}

test "loss: stream_data is freed on ack and transferred on loss" {
    const testing = std.testing;
    const a = testing.allocator;
    var ld = try LossDetector.init(a);
    defer ld.deinit(a);
    var rtt = RttEstimator{};

    // Pkt 0: will be acked → expect stream_data freed by onAck.
    const buf0 = try a.dupe(u8, "ack-me");
    _ = ld.onPacketSent(.{
        .pn = 0,
        .send_time_ms = 100,
        .size = 100,
        .ack_eliciting = true,
        .in_flight = true,
        .has_stream_data = true,
        .stream_id = 42,
        .stream_offset = 0,
        .stream_data = buf0,
    });

    // Pkts 1..5 keep the gap visible so pkt 1 hits the packet-threshold loss path.
    var i: u64 = 1;
    while (i < 6) : (i += 1) {
        _ = ld.onPacketSent(.{
            .pn = i,
            .send_time_ms = 110 + i * 10,
            .size = 100,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    // Pkt 1: will be lost (k_packet_threshold trips when pn 5 is acked).
    // Caller owns stream_data after it lands in lost_buf; we free it below.
    const buf1 = try a.dupe(u8, "retransmit-me");
    // Find pkt 1 and attach buf to it so we can verify ownership transfer.
    for (ld.sent[0..ld.sent_count]) |*p| {
        if (p.pn == 1) {
            p.has_stream_data = true;
            p.stream_id = 7;
            p.stream_offset = 9;
            p.stream_data = buf1;
            break;
        }
    }

    var lost_buf: [8]SentPacket = undefined;
    // Ack pn 0 (frees buf0 internally), then ack pn 5 separately so pn 1
    // is declared lost via k_packet_threshold.
    const r0 = try ld.onAck(.application, 0, 0, 0, 200, &rtt, &lost_buf, a);
    try testing.expectEqual(@as(usize, 0), r0.lost_count);

    const r1 = try ld.onAck(.application, 5, 0, 0, 200, &rtt, &lost_buf, a);
    try testing.expect(r1.lost_count >= 1);
    // Find the lost descriptor that owns the heap slice.
    var saw_transfer = false;
    var li: usize = 0;
    while (li < r1.lost_count) : (li += 1) {
        if (lost_buf[li].pn == 1) {
            try testing.expect(lost_buf[li].stream_data != null);
            a.free(lost_buf[li].stream_data.?);
            saw_transfer = true;
        }
    }
    try testing.expect(saw_transfer);
}

test "loss: streamDataLooksFreeable rejects corrupt lengths, accepts sane ones" {
    const testing = std.testing;
    // Garbage lengths (uninitialized SentPacket) are rejected — predicate is
    // pure, so this asserts the skip decision without emitting the wrapper's
    // warning (which would trip the test runner's no-log policy).
    var stack_byte: u8 = 0;
    const huge: []const u8 = @as([*]const u8, @ptrCast(&stack_byte))[0 .. max_sane_stream_data_len + 1];
    try testing.expect(!streamDataLooksFreeable(huge));
    const empty: []const u8 = @as([*]const u8, @ptrCast(&stack_byte))[0..0];
    try testing.expect(!streamDataLooksFreeable(empty));

    // A sane-length slice passes, and freeStreamDataChecked frees it cleanly
    // (testing.allocator would flag a leak if the guard wrongly skipped it).
    const a = testing.allocator;
    const real = try a.dupe(u8, "retransmit");
    try testing.expect(streamDataLooksFreeable(real));
    try testing.expect(freeStreamDataChecked(a, real, 9, 1));
}

test "loss: stream_data ownership survives adversarial send/ack/retransmit churn at cap" {
    // Reproduces the io.zig client retransmit ownership protocol under heavy
    // load near the in-flight tracking cap:
    //   - onPacketSent with a heap-owned stream_data slice (dup'd here, like
    //     clientSendRawStreamFrame's `dupe`).  On `false` (LD full) the caller
    //     owns the slice and must free it (io.zig:7571).
    //   - onAck frees acked stream_data internally and TRANSFERS lost
    //     stream_data into lost_buf (ownership moves to caller), capping at
    //     lost_buf.len and freeing the overflow internally.
    //   - For each returned lost descriptor with stream_data, re-send it under
    //     a FRESH pn transferring ownership back into the LD (io.zig:8941).
    // testing.allocator flags any double-free / use-after-free / leak.
    const testing = std.testing;
    const a = testing.allocator;
    var ld = try LossDetector.init(a);
    defer ld.deinit(a);
    var rtt = RttEstimator{};

    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rand = prng.random();

    var next_pn: u64 = 0;
    var now: u64 = 1000;
    var lost_buf: [32]SentPacket = undefined;

    // Helper: emit one fresh STREAM packet with a heap stream_data slice,
    // honoring the caller-frees-on-false contract.
    const Helper = struct {
        fn send(d: *LossDetector, alloc: std.mem.Allocator, pn: u64, t: u64, sd: []u8) void {
            const recorded = d.onPacketSent(.{
                .pn = pn,
                .send_time_ms = @intCast(t),
                .size = sd.len + 30,
                .ack_eliciting = true,
                .in_flight = true,
                .has_stream_data = true,
                .stream_id = 4,
                .stream_offset = pn,
                .stream_data = sd,
            });
            if (!recorded) alloc.free(sd); // io.zig:7571 contract
        }
    };

    var iter: usize = 0;
    while (iter < 200_000) : (iter += 1) {
        now += 1 + rand.uintLessThan(u64, 5);

        // Burst of fresh sends to push toward the cap.
        const burst = 1 + rand.uintLessThan(usize, 6);
        var b: usize = 0;
        while (b < burst) : (b += 1) {
            const len = 1 + rand.uintLessThan(usize, 1200);
            const sd = a.alloc(u8, len) catch return error.OutOfMemory;
            Helper.send(&ld, a, next_pn, now, sd);
            next_pn += 1;
        }

        if (ld.sent_count == 0) continue;

        // Ack near the tail, sometimes with a gap so older PNs are declared
        // lost by the packet/time threshold.
        const top = next_pn - 1;
        const range: u64 = rand.uintLessThan(u64, 8);
        const largest = top -| rand.uintLessThan(u64, 3);
        const first_range = @min(range, largest);

        const r = ld.onAck(.application, largest, first_range, 0, now, &rtt, &lost_buf, a) catch {
            continue;
        };

        // Retransmit every lost descriptor that carried stream_data, under a
        // fresh pn — ownership transfers back into the LD (or is freed on the
        // caller-frees contract when the LD is full).
        var li: usize = 0;
        while (li < r.lost_count) : (li += 1) {
            if (lost_buf[li].stream_data) |sbuf| {
                Helper.send(&ld, a, next_pn, now, sbuf);
                next_pn += 1;
            }
        }

        // Occasionally advance time far enough to flush the whole window via
        // the time-threshold loss path, exercising large single-ACK losses.
        if (iter % 4096 == 0 and ld.sent_count > 0) {
            now += 10_000;
            const flush = ld.onAck(.application, next_pn -| 1, 0, 0, now, &rtt, &lost_buf, a) catch continue;
            var fi: usize = 0;
            while (fi < flush.lost_count) : (fi += 1) {
                if (lost_buf[fi].stream_data) |sbuf| a.free(sbuf);
            }
        }
    }
    // ld.deinit frees any stream_data still tracked — testing.allocator will
    // flag a leak if the ownership accounting dropped a buffer.
}

test "loss: per-PN-space ACK only affects matching space" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};

    _ = ld.onPacketSent(.{ .pn = 0, .send_time_ms = 190, .size = 50, .ack_eliciting = true, .in_flight = true, .space = .handshake });
    _ = ld.onPacketSent(.{ .pn = 0, .send_time_ms = 195, .size = 50, .ack_eliciting = true, .in_flight = true, .space = .application });
    _ = ld.onPacketSent(.{ .pn = 1, .send_time_ms = 196, .size = 50, .ack_eliciting = true, .in_flight = true, .space = .application });

    var lost_buf: [8]SentPacket = undefined;
    const r = try ld.onAck(.application, 1, 1, 0, 200, &rtt, &lost_buf, testing.allocator);
    try testing.expectEqual(@as(usize, 0), r.lost_count);
    try testing.expectEqual(@as(usize, 1), ld.sent_count);
    try testing.expectEqual(PacketNumberSpace.handshake, ld.sent[0].space);
    try testing.expectEqual(@as(u64, 0), ld.sent[0].pn);
}

test "loss: abandonSpace drops only the targeted PN space" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    _ = ld.onPacketSent(.{ .pn = 0, .send_time_ms = 100, .size = 50, .ack_eliciting = true, .in_flight = true, .space = .initial });
    _ = ld.onPacketSent(.{ .pn = 1, .send_time_ms = 110, .size = 50, .ack_eliciting = true, .in_flight = true, .space = .handshake });
    _ = ld.onPacketSent(.{ .pn = 2, .send_time_ms = 120, .size = 50, .ack_eliciting = true, .in_flight = true, .space = .application });
    ld.abandonSpace(.initial, testing.allocator);
    ld.abandonSpace(.handshake, testing.allocator);
    try testing.expectEqual(@as(usize, 1), ld.sent_count);
    try testing.expectEqual(PacketNumberSpace.application, ld.sent[0].space);
    try testing.expectEqual(@as(u64, 2), ld.sent[0].pn);
    try testing.expect(!ld.inflightInSpace(.initial));
    try testing.expect(!ld.inflightInSpace(.handshake));
    try testing.expect(ld.inflightInSpace(.application));
}

test "deque: contiguous front ack pops front, higher-pn suffix preserved in order" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};
    var pn: u64 = 0;
    while (pn < 10) : (pn += 1) {
        _ = ld.onPacketSent(.{ .pn = pn, .send_time_ms = 100 + pn, .size = 100, .ack_eliciting = true, .in_flight = true });
    }
    try testing.expectEqual(@as(usize, 10), ld.sent_count);
    // Ack [0..4]: largest=4, first_ack_range=4. Healthy contiguous front ack.
    var lost_buf: [8]SentPacket = undefined;
    const r = try ld.onAck(.application, 4, 4, 0, 200, &rtt, &lost_buf, testing.allocator);
    try testing.expectEqual(@as(usize, 0), r.lost_count);
    try testing.expectEqual(@as(u64, 500), r.bytes_acked);
    // 5 remain (pns 5..9), popped off the front so head advanced past them.
    try testing.expectEqual(@as(usize, 5), ld.sent_count);
    try testing.expectEqual(@as(usize, 5), ld.head);
    var i: usize = 0;
    while (i < ld.sent_count) : (i += 1) {
        try testing.expectEqual(@as(u64, 5) + i, ld.sent[ld.head + i].pn);
    }
    try testing.expectEqual(@as(u64, 9), ld.lastSentPtr().?.pn);
}

test "deque: fully acked resets head to 0 and stays usable" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};
    var pn: u64 = 0;
    while (pn < 3) : (pn += 1) {
        _ = ld.onPacketSent(.{ .pn = pn, .send_time_ms = 10, .size = 1, .ack_eliciting = true, .in_flight = true });
    }
    var lost_buf: [4]SentPacket = undefined;
    _ = try ld.onAck(.application, 2, 2, 0, 20, &rtt, &lost_buf, testing.allocator);
    try testing.expectEqual(@as(usize, 0), ld.sent_count);
    try testing.expectEqual(@as(usize, 0), ld.head);
    // Reusable: a fresh send lands at index 0.
    try testing.expect(ld.onPacketSent(.{ .pn = 3, .send_time_ms = 30, .size = 1, .ack_eliciting = true, .in_flight = true }));
    try testing.expectEqual(@as(u64, 3), ld.sent[ld.head].pn);
}

test "deque: reorder gap — front losses popped, gap-keepers retained, acked-behind processed via fallback" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};
    var pn: u64 = 0;
    while (pn < 5) : (pn += 1) {
        _ = ld.onPacketSent(.{ .pn = pn, .send_time_ms = 100, .size = 100, .ack_eliciting = true, .in_flight = true });
    }
    // Ack only pn 4 (largest=4, first_ack_range=0). now == send_time ⇒ no
    // time-threshold loss. pn0,pn1 lost by packet threshold (4 >= pn+3); pn2,pn3
    // are gap-keepers (retained); pn4 acked. The front-pop stops at pn2 (keep)
    // and the fallback compaction handles pn4 behind it.
    var lost_buf: [8]SentPacket = undefined;
    const r = try ld.onAck(.application, 4, 0, 0, 100, &rtt, &lost_buf, testing.allocator);
    try testing.expectEqual(@as(usize, 2), r.lost_count);
    try testing.expectEqual(@as(u64, 100), r.bytes_acked);
    try testing.expectEqual(@as(usize, 2), ld.sent_count);
    try testing.expectEqual(@as(u64, 2), ld.sent[ld.head].pn);
    try testing.expectEqual(@as(u64, 3), ld.sent[ld.head + 1].pn);
}

test "deque: head-wrap compaction preserves a sliding in-flight window" {
    const testing = std.testing;
    var ld = try LossDetector.init(testing.allocator);
    defer ld.deinit(testing.allocator);
    var rtt = RttEstimator{};
    var lost_buf: [4]SentPacket = undefined;
    const win: u64 = 4;
    var pn: u64 = 0;
    while (pn < win) : (pn += 1) {
        _ = ld.onPacketSent(.{ .pn = pn, .send_time_ms = pn, .size = 1, .ack_eliciting = true, .in_flight = true });
    }
    // Slide a 4-deep window past the end of the backing array (≥1 compaction).
    const stop = win + LossDetector.max_tracked_packets + 32;
    while (pn < stop) : (pn += 1) {
        try testing.expect(ld.onPacketSent(.{ .pn = pn, .send_time_ms = pn, .size = 1, .ack_eliciting = true, .in_flight = true }));
        // Ack the oldest in-flight pn (front); now == newest send_time so the
        // 4 higher-pn survivors are neither time- nor packet-threshold lost.
        const r = try ld.onAck(.application, pn - win, 0, 0, pn + 1, &rtt, &lost_buf, testing.allocator);
        try testing.expectEqual(@as(usize, 0), r.lost_count);
        try testing.expectEqual(win, @as(u64, @intCast(ld.sent_count)));
        try testing.expectEqual(pn - win + 1, ld.sent[ld.head].pn);
    }
}
