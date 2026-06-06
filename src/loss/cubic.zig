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

/// CUBIC scaling constant C = 0.4.
/// We use fixed-point: C_NUM/C_DEN = 4/10 = 0.4.
const C_NUM: u64 = 4;
const C_DEN: u64 = 10;

/// Multiplicative decrease factor β = 0.7.
/// BETA_NUM/BETA_DEN = 7/10 = 0.7.
const BETA_NUM: u64 = 7;
const BETA_DEN: u64 = 10;

pub const Cubic = struct {
    /// Congestion window in bytes.
    cwnd: u64 = 10 * mss,
    /// Slow start threshold.
    ssthresh: u64 = max_cwnd,
    /// Bytes in flight.
    bytes_in_flight: u64 = 0,
    /// State.
    state: nr.CcState = .slow_start,
    /// W_max: window size (in MSS) at the last loss event.
    w_max: u64 = 0,
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

    pub fn init() Cubic {
        return .{};
    }

    /// Called when packets are acknowledged.
    pub fn onAck(self: *Cubic, bytes_acked: u64) void {
        self.bytes_in_flight -|= bytes_acked;

        if (self.state == .recovery) {
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
        // Save W_max before reducing (in MSS units).
        self.w_max = self.cwnd / mss;
        // Multiplicative decrease: cwnd = cwnd × β.
        self.ssthresh = @max(self.cwnd * BETA_NUM / BETA_DEN, 2 * mss);
        self.cwnd = self.ssthresh;
        self.state = .recovery;
        // Reset epoch so next congestion avoidance starts fresh.
        self.epoch_start_ms = null;
        self.bytes_acked_ca = 0;
    }

    /// Called when persistent congestion is detected (RFC 9002 §7.6.3).
    /// Collapse to the minimum window and re-enter slow start; clear the
    /// CUBIC epoch so the next recovery starts fresh.
    pub fn onPersistentCongestion(self: *Cubic) void {
        self.cwnd = nr.minimum_window;
        self.state = .slow_start;
        self.epoch_start_ms = null;
        self.bytes_acked_ca = 0;
        self.end_of_recovery = null;
        self.w_max = 0;
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
    cc.onAck(mss);
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

test "cubic: integer cube root" {
    const testing = std.testing;
    try testing.expectEqual(@as(u64, 0), intCbrt(0));
    try testing.expectEqual(@as(u64, 1), intCbrt(1));
    try testing.expectEqual(@as(u64, 2), intCbrt(8));
    try testing.expectEqual(@as(u64, 3), intCbrt(27));
    try testing.expectEqual(@as(u64, 10), intCbrt(1000));
    try testing.expectEqual(@as(u64, 10), intCbrt(1100)); // floor
}

test "cubic: can_send check" {
    const testing = std.testing;
    var cc = Cubic.init();
    cc.cwnd = 2 * mss;
    cc.bytes_in_flight = 2 * mss;
    try testing.expect(!cc.canSend(1));
    cc.onAck(mss);
    try testing.expect(cc.canSend(mss));
}
