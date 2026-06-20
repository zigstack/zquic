//! CUBIC congestion control (RFC 9438 / RFC 8312).
//!
//! CUBIC uses a cubic function for window growth in congestion avoidance,
//! achieving better throughput on high-BDP paths than NewReno while remaining
//! TCP-friendly.  The window function is:
//!
//!   W(t) = C × (t − K)³ + W_max
//!
//! where:
//!   C     = 0.4 (scaling constant)
//!   K     = ∛(W_max × β / C)  (time to reach W_max after loss)
//!   β     = 0.7  (multiplicative decrease factor)
//!   W_max = cwnd at the time of the last loss event
//!   t     = elapsed time since the last loss event
//!
//! This module implements the same interface as NewReno so the connection
//! can switch between controllers via a tagged union.

const std = @import("std");
const compat = @import("../compat.zig");
const nr = @import("congestion.zig");

pub const mss: u64 = nr.mss;
const max_cwnd: u64 = 64 * 1024 * 1024;
/// RFC 9002 §7.2 initial congestion window (10 × max_datagram_size, capped).
pub const rfc_initial_window: u64 = 14_720;
/// RFC 9002 §7.6.3 minimum congestion window (2 × MSS).
pub const rfc_minimum_window: u64 = 2 * mss;
/// Libp2p/gossip-tuned initial window (32 × MSS) for bursty single-stream workloads.
pub const aggressive_initial_window: u64 = 32 * mss;
/// Raised post-loss floor for low-RTT spurious-reorder paths (10 × MSS).
pub const aggressive_minimum_window: u64 = 10 * mss;

/// CUBIC scaling constant C = 0.4.
/// We use fixed-point: C_NUM/C_DEN = 4/10 = 0.4.
const C_NUM: u64 = 4;
const C_DEN: u64 = 10;

/// Multiplicative decrease factor β = 0.7.
/// BETA_NUM/BETA_DEN = 7/10 = 0.7.
const BETA_NUM: u64 = 7;
const BETA_DEN: u64 = 10;

pub const Cubic = struct {
    /// Congestion window in bytes (RFC 9002 §7.2 default).
    cwnd: u64 = rfc_initial_window,
    /// Post-loss floor (RFC 9002 §7.6.3 default; override via `CcOptions`).
    min_window: u64 = nr.minimum_window,
    /// Slow start threshold.
    ssthresh: u64 = max_cwnd,
    /// Bytes in flight.
    bytes_in_flight: u64 = 0,
    /// State.
    state: nr.CcState = .slow_start,
    /// W_max: window size (in MSS) at the last loss event.
    w_max: u64 = 0,
    /// W_max from the previous congestion event (RFC 9438 §4.7 fast convergence).
    w_max_last: u64 = 0,
    /// Epoch start: timestamp (ms) when the current congestion avoidance epoch started.
    epoch_start_ms: ?i64 = null,
    /// K: time (ms) for the cubic function to reach W_max.
    k_ms: u64 = 0,
    /// Largest ACKed packet number in the current recovery period.
    end_of_recovery: ?u64 = null,
    /// TCP-friendly estimate of cwnd (for the TCP-friendliness check).
    tcp_cwnd: u64 = 0,
    /// Bytes ACKed in current congestion avoidance epoch (for TCP-friendly estimate).
    bytes_acked_ca: u64 = 0,
    /// Diagnostics (not used in CC math): see NewReno.
    congestion_events: u64 = 0,
    total_bytes_acked: u64 = 0,

    pub fn init() Cubic {
        return .{};
    }

    pub fn initWithOptions(opts: nr.CcOptions) Cubic {
        return .{ .cwnd = opts.initial_window, .min_window = opts.minimum_window };
    }

    /// Called when packets are acknowledged. `largest_acked_pn` is the largest
    /// packet number newly acknowledged by this ACK; it gates recovery exit.
    pub fn onAck(self: *Cubic, bytes_acked: u64, largest_acked_pn: u64) void {
        self.total_bytes_acked +|= bytes_acked;
        self.bytes_in_flight -|= bytes_acked;

        if (self.state == .recovery) {
            // RFC 9002 §7.3.2: remain in recovery — and keep reacting to loss
            // only once per round trip — until an ACK arrives for a packet sent
            // *after* the recovery period began. Exiting on the first ACK and
            // clearing `end_of_recovery` (as this code previously did) destroys
            // the once-per-flight loss gate in `onLoss`: the next loss detected
            // from the same flight re-enters recovery and cuts cwnd again, so a
            // single congestion episode collapses cwnd to the floor over many
            // ACKs (congestion_events climbing into the thousands).
            if (self.end_of_recovery) |eor| {
                if (largest_acked_pn <= eor) return; // pre-recovery ack: no growth, stay in recovery
            }
            self.state = .congestion_avoidance;
            self.end_of_recovery = null;
        }

        if (self.state == .slow_start) {
            self.cwnd +|= bytes_acked;
            if (self.cwnd >= self.ssthresh) {
                self.state = .congestion_avoidance;
                self.epoch_start_ms = null; // reset epoch on entering CA
            }
        } else if (self.state == .congestion_avoidance) {
            self.updateCubic(bytes_acked);
        }
    }

    fn updateCubic(self: *Cubic, bytes_acked: u64) void {
        const now_ms = compat.milliTimestamp();

        // Start a new epoch if needed.
        if (self.epoch_start_ms == null) {
            self.epoch_start_ms = now_ms;
            if (self.cwnd < self.w_max * mss) {
                // Compute K = ∛(W_max × (1 - β) / C) in milliseconds.
                // K = ∛((w_max * (1 - 0.7) / 0.4)) seconds → convert to ms.
                // K = ∛(w_max * 3 / 4) seconds (since (1-0.7)/0.4 = 0.75).
                // We compute in integer: K_s³ = w_max * 3 / 4 (in MSS units).
                const w_max_mss = self.w_max;
                const val = w_max_mss * 3 / 4; // (1-β)/C = 0.3/0.4 = 0.75
                self.k_ms = intCbrt(val) * 1000; // seconds to ms
            } else {
                self.k_ms = 0;
            }
            self.tcp_cwnd = self.cwnd;
        }

        const epoch_start = self.epoch_start_ms orelse now_ms;
        const t_ms: u64 = @intCast(@max(now_ms - epoch_start, 0));

        // W_cubic(t) = C × (t - K)³ + W_max  (in MSS units, t in seconds)
        // We compute in integer with ms precision:
        //   W = C_NUM/C_DEN × ((t_ms - k_ms)/1000)³ + w_max  (MSS units)
        // Rearranged to avoid floating point:
        //   diff = t_ms - k_ms (signed, in ms)
        //   W_mss = C_NUM × diff³ / (C_DEN × 1000³) + w_max
        const diff: i64 = @as(i64, @intCast(t_ms)) - @as(i64, @intCast(self.k_ms));
        const diff_cubed: i64 = @divTrunc(diff * diff * diff, 1_000_000_000); // diff³/10⁹
        const cubic_mss: i64 = @as(i64, @intCast(self.w_max)) + @divTrunc(diff_cubed * @as(i64, @intCast(C_NUM)), @as(i64, @intCast(C_DEN)));

        const w_cubic: u64 = if (cubic_mss > 0)
            @min(@as(u64, @intCast(cubic_mss)) * mss, max_cwnd)
        else
            self.cwnd;

        // TCP-friendly estimate: NewReno-like linear growth.
        self.bytes_acked_ca += bytes_acked;
        while (self.bytes_acked_ca >= self.tcp_cwnd) {
            self.bytes_acked_ca -= self.tcp_cwnd;
            self.tcp_cwnd = @min(self.tcp_cwnd + mss, max_cwnd);
        }

        // Use the larger of CUBIC and TCP-friendly estimates (RFC 9438 §4.4).
        const target = @max(w_cubic, self.tcp_cwnd);
        if (target > self.cwnd) {
            self.cwnd = target;
        }
    }

    /// Called on packet loss.
    pub fn onLoss(self: *Cubic, largest_lost_pn: u64) void {
        // Only react to loss once per flight (RFC 9002 §7.3.2).
        if (self.end_of_recovery) |eor| {
            if (largest_lost_pn <= eor) return;
        }

        self.end_of_recovery = largest_lost_pn;
        const cwnd_mss = self.cwnd / mss;
        // RFC 9438 §4.7 fast convergence: when cwnd < prior W_max, scale down.
        if (cwnd_mss < self.w_max_last) {
            self.w_max = cwnd_mss * 17 / 20; // (1 + β) / 2 = 0.85
        } else {
            self.w_max = cwnd_mss;
        }
        self.w_max_last = self.w_max;
        // Multiplicative decrease: cwnd = cwnd × β.
        self.ssthresh = @max(self.cwnd * BETA_NUM / BETA_DEN, self.min_window);
        self.cwnd = self.ssthresh;
        self.state = .recovery;
        // Reset epoch so next congestion avoidance starts fresh.
        self.epoch_start_ms = null;
        self.bytes_acked_ca = 0;
        self.congestion_events += 1;
    }

    /// Called when persistent congestion is detected (RFC 9002 §7.6.3).
    /// Collapse to the minimum window and re-enter slow start; clear the
    /// CUBIC epoch so the next recovery starts fresh.
    pub fn onPersistentCongestion(self: *Cubic) void {
        self.cwnd = self.min_window;
        self.state = .slow_start;
        self.epoch_start_ms = null;
        self.bytes_acked_ca = 0;
        self.end_of_recovery = null;
        self.w_max = 0;
        self.w_max_last = 0;
        self.k_ms = 0;
        self.tcp_cwnd = 0;
    }

    /// ECN-CE feedback or other peer-signalled congestion event.  Same
    /// reaction as a packet-loss event — gated by `end_of_recovery`.
    pub fn onCongestionEvent(self: *Cubic, largest_acked_pn: u64) void {
        self.onLoss(largest_acked_pn);
    }

    /// Called when a packet is sent.
    pub fn onPacketSent(self: *Cubic, bytes: u64) void {
        self.bytes_in_flight +|= bytes;
    }

    /// Returns the send credit (bytes allowed to be in flight).
    pub fn sendCredit(self: *const Cubic) u64 {
        return self.cwnd -| self.bytes_in_flight;
    }

    /// True if we may send more data (sender-side congestion check).
    pub fn canSend(self: *const Cubic, packet_size: u64) bool {
        return self.bytes_in_flight + packet_size <= self.cwnd;
    }
};

/// Integer cube root via Newton's method.
fn intCbrt(n: u64) u64 {
    if (n == 0) return 0;
    if (n < 8) return 1;
    var x: u64 = n;
    var y: u64 = (2 * x + n / (x * x)) / 3;
    while (y < x) {
        x = y;
        // Guard against division by zero from very small x.
        const x_sq = x *| x;
        if (x_sq == 0) break;
        y = (2 * x + n / x_sq) / 3;
    }
    return x;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "cubic: slow start growth" {
    const testing = std.testing;
    var cc = Cubic.init();
    try testing.expectEqual(nr.CcState.slow_start, cc.state);
    const initial_cwnd = cc.cwnd;

    cc.onPacketSent(mss);
    cc.onAck(mss, 1);
    try testing.expectEqual(initial_cwnd + mss, cc.cwnd);
}

test "cubic: loss triggers recovery with β=0.7" {
    const testing = std.testing;
    var cc = Cubic.init();
    cc.cwnd = 100 * mss;
    cc.bytes_in_flight = 50 * mss;

    cc.onLoss(5);
    try testing.expectEqual(nr.CcState.recovery, cc.state);
    // ssthresh = cwnd × 0.7 = 100 × 0.7 = 70 MSS
    try testing.expectEqual(@as(u64, 70 * mss), cc.ssthresh);
    try testing.expectEqual(@as(u64, 70 * mss), cc.cwnd);
    // W_max should be saved.
    try testing.expectEqual(@as(u64, 100), cc.w_max);
}

test "cubic: one congestion episode cuts cwnd once across many ACKs" {
    const testing = std.testing;
    var cc = Cubic.init();
    cc.state = .congestion_avoidance;
    cc.cwnd = 100 * mss;
    cc.bytes_in_flight = 100 * mss;

    // A flight (PNs 0..40) suffers loss. Loss is detected on PN 30 first, then
    // the loss detector dribbles out more losses (PNs 20, 25) on later ACKs of
    // the SAME flight — exactly what packet/time-threshold detection does.
    // ACKs and losses interleave, as in the real recv loop (onAck then onLoss).
    cc.onLoss(30); // recovery starts; end_of_recovery = 30
    try testing.expectEqual(nr.CcState.recovery, cc.state);
    const after_first = cc.cwnd; // 70 * mss
    try testing.expectEqual(@as(u64, 1), cc.congestion_events);

    // ACK of a pre-recovery packet (PN 10 <= 30): must NOT exit recovery and
    // must NOT let the next loss re-trigger a cut.
    cc.onAck(mss, 10);
    try testing.expectEqual(nr.CcState.recovery, cc.state);
    cc.onLoss(25); // same flight, <= end_of_recovery → gated, no second cut
    cc.onAck(mss, 12);
    cc.onLoss(20); // still gated
    try testing.expectEqual(@as(u64, 1), cc.congestion_events);
    try testing.expectEqual(after_first, cc.cwnd); // cwnd unchanged — no cascade

    // An ACK for a packet sent AFTER recovery began (PN 41 > 30) ends recovery.
    cc.onAck(mss, 41);
    try testing.expectEqual(nr.CcState.congestion_avoidance, cc.state);

    // A genuinely new congestion episode (PN past end_of_recovery) cuts again.
    cc.onLoss(50);
    try testing.expectEqual(@as(u64, 2), cc.congestion_events);
    try testing.expectEqual(nr.CcState.recovery, cc.state);
}

test "cubic: integer cube root" {
    const testing = std.testing;
    try testing.expectEqual(@as(u64, 0), intCbrt(0));
    try testing.expectEqual(@as(u64, 1), intCbrt(1));
    try testing.expectEqual(@as(u64, 2), intCbrt(8));
    try testing.expectEqual(@as(u64, 3), intCbrt(27));
    try testing.expectEqual(@as(u64, 10), intCbrt(1000));
    try testing.expectEqual(@as(u64, 10), intCbrt(1100)); // floor
}

test "cubic: fast convergence scales W_max when cwnd drops" {
    const testing = std.testing;
    var cc = Cubic.init();
    cc.cwnd = 80 * mss;
    cc.w_max_last = 100; // prior W_max in MSS units
    cc.onLoss(5);
    // cwnd (80) < w_max_last (100) → W_max = 80 * 0.85 = 68
    try testing.expectEqual(@as(u64, 68), cc.w_max);
    try testing.expectEqual(@as(u64, 68), cc.w_max_last);
}

test "cubic: can_send check" {
    const testing = std.testing;
    var cc = Cubic.init();
    cc.cwnd = 2 * mss;
    cc.bytes_in_flight = 2 * mss;
    try testing.expect(!cc.canSend(1));
    cc.onAck(mss, 1);
    try testing.expect(cc.canSend(mss));
}
