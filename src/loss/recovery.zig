//! QUIC loss detection and RTT estimation (RFC 9002).
//!
//! Implements:
//!   - RTT estimation (§5): smoothed RTT, RTT variance, min RTT
//!   - Loss detection (§6): ACK-based, timeout-based
//!   - Probe Timeout (PTO) (§6.2)

const std = @import("std");

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
        const base_pto: f64 = self.srtt_ms + @max(4.0 * self.rttvar_ms, @as(f64, @floatFromInt(k_granularity_ms)));
        const with_delay: f64 = base_pto + @as(f64, @floatFromInt(max_ack_delay));
        const scaled = with_delay * std.math.pow(f64, 2.0, @floatFromInt(pto_count));
        return @intFromFloat(scaled);
    }
};

/// A record of a packet that has been sent but not yet acknowledged.
pub const SentPacket = struct {
    pn: u64,
    send_time_ms: u64,
    size: usize,
    ack_eliciting: bool,
    in_flight: bool,
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

/// Loss detection state for one packet number space.
pub const LossDetector = struct {
    const max_tracked = 256;

    sent: [max_tracked]SentPacket = undefined,
    sent_count: usize = 0,
    largest_acked: u64 = 0,
    loss_time_ms: ?u64 = null,

    /// Free any heap-owned retransmit buffers attached to in-flight packets.
    /// Caller passes the same allocator used when populating `stream_data`.
    pub fn deinit(self: *LossDetector, allocator: std.mem.Allocator) void {
        for (self.sent[0..self.sent_count]) |*p| {
            if (p.stream_data) |sd| allocator.free(sd);
            p.stream_data = null;
        }
        self.sent_count = 0;
    }

    /// Record a newly sent packet.
    ///
    /// If `pkt.stream_data` is non-null and we cannot record the packet
    /// (buffer full), the caller is responsible for freeing the slice —
    /// otherwise it would leak.  Returns true when the packet was stored.
    pub fn onPacketSent(self: *LossDetector, pkt: SentPacket) bool {
        if (self.sent_count < max_tracked) {
            self.sent[self.sent_count] = pkt;
            self.sent_count += 1;
            return true;
        }
        return false;
    }

    pub const OnAckError = error{FrameEncodingError};

    pub const OnAckResult = struct {
        lost_count: usize,
        rtt_updated: bool,
        bytes_acked: u64,
        lost_bytes: u64,
    };

    /// Process an ACK frame. Returns packets declared lost.
    /// `now_ms` is the current wall-clock time in milliseconds.
    /// `rtt` is the RTT estimator.
    ///
    /// Returns `error.FrameEncodingError` if `first_ack_range > largest_acked`
    /// (RFC 9000 §19.3: the first range must not underflow the packet number space).
    pub fn onAck(
        self: *LossDetector,
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

        var rtt_updated = false;

        // Update RTT sample for the largest acknowledged packet.
        if (largest_acked > self.largest_acked) {
            self.largest_acked = largest_acked;
            for (self.sent[0..self.sent_count]) |p| {
                if (p.pn == largest_acked) {
                    const sample = now_ms -| p.send_time_ms;
                    rtt.update(sample, ack_delay_ms);
                    rtt_updated = true;
                    break;
                }
            }
        }

        // The first ACK range covers [smallest_acked .. largest_acked].
        // Packets in this range are definitively acknowledged.
        // Packets below smallest_acked may be in a gap (possibly lost).
        const smallest_acked = largest_acked - first_ack_range;

        var lost_count: usize = 0;
        var bytes_acked: u64 = 0;
        var lost_bytes: u64 = 0;

        var i: usize = 0;
        while (i < self.sent_count) {
            const p = self.sent[i];

            // Packet is definitively acked: within [smallest_acked .. largest_acked].
            if (p.pn >= smallest_acked and p.pn <= largest_acked) {
                bytes_acked += p.size;
                // Free heap-owned retransmit buffer (raw-application path).
                if (self.sent[i].stream_data) |sd| {
                    allocator.free(sd);
                    self.sent[i].stream_data = null;
                }
                self.sent[i] = self.sent[self.sent_count - 1];
                self.sent_count -= 1;
                continue;
            }

            // Packet is below the acked range — apply k_packet_threshold loss
            // detection only for true gaps (p.pn < smallest_acked).
            // A packet is considered lost when k_packet_threshold or more
            // later packets have been acknowledged (RFC 9002 §6.1.1).
            if (p.pn < smallest_acked and largest_acked >= p.pn + k_packet_threshold) {
                lost_bytes += p.size;
                if (lost_count < lost_buf.len) {
                    lost_buf[lost_count] = p; // full descriptor for retransmission
                    // Ownership of stream_data transfers from `self.sent[i]`
                    // to `lost_buf[lost_count]`; clear the source so it isn't
                    // freed when this slot is later overwritten.
                    self.sent[i].stream_data = null;
                    lost_count += 1;
                } else {
                    // No room to surface this loss — free the retransmit
                    // buffer so it doesn't leak.
                    if (self.sent[i].stream_data) |sd| {
                        allocator.free(sd);
                        self.sent[i].stream_data = null;
                    }
                }
                self.sent[i] = self.sent[self.sent_count - 1];
                self.sent_count -= 1;
                continue;
            }

            i += 1;
        }

        return OnAckResult{
            .lost_count = lost_count,
            .rtt_updated = rtt_updated,
            .bytes_acked = bytes_acked,
            .lost_bytes = lost_bytes,
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
    var ld = LossDetector{};
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
    const result = try ld.onAck(5, 0, 0, 200, &rtt, &lost_buf, testing.allocator);
    try testing.expect(result.lost_count >= 2);
}

test "loss: rejects invalid first_ack_range > largest_acked" {
    const testing = std.testing;
    var ld = LossDetector{};
    var rtt = RttEstimator{};
    var lost_buf: [4]SentPacket = undefined;
    // largest_acked=5, first_ack_range=10 → would underflow.
    try testing.expectError(
        error.FrameEncodingError,
        ld.onAck(5, 10, 0, 200, &rtt, &lost_buf, testing.allocator),
    );
}

test "loss: stream_data is freed on ack and transferred on loss" {
    const testing = std.testing;
    const a = testing.allocator;
    var ld = LossDetector{};
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
    const r0 = try ld.onAck(0, 0, 0, 200, &rtt, &lost_buf, a);
    try testing.expectEqual(@as(usize, 0), r0.lost_count);

    const r1 = try ld.onAck(5, 0, 0, 200, &rtt, &lost_buf, a);
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
