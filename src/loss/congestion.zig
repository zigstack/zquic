//! New Reno congestion control (RFC 9002 §7, RFC 5681).
//!
//! States:
//!   Slow Start: cwnd grows by one MSS per ACK (doubles per RTT)
//!   Congestion Avoidance: cwnd grows by MSS²/cwnd per byte ACKed
//!   Recovery: after loss, cwnd = ssthresh = max(cwnd/2, 2*MSS)

const std = @import("std");

/// Maximum segment size (bytes) for congestion control calculations.
/// Set to 1350 to match typical QUIC payload sizes (1500 MTU - headers/AEAD).
/// This only affects CC window math (initial cwnd, CA growth, ssthresh floor),
/// not actual packet sizing which is governed by MAX_DATAGRAM_SIZE (1500).
pub const mss: u64 = 1350;
/// Maximum congestion window (bytes).
const max_cwnd: u64 = 64 * 1024 * 1024; // 64 MB
/// RFC 9002 §7.2 initial congestion window (10 × max_datagram_size, capped at 14,720).
pub const rfc_initial_window: u64 = 14_720;
/// RFC 9002 §7.6.3 minimum congestion window (2 × MSS).
pub const rfc_minimum_window: u64 = 2 * mss;
/// Libp2p/gossip-tuned initial window for bursty single-stream workloads.
pub const aggressive_initial_window: u64 = 32 * mss;
/// Raised post-loss floor for low-RTT spurious-reorder paths.
pub const aggressive_minimum_window: u64 = 10 * mss;
/// Default minimum window (RFC-compliant).
pub const minimum_window: u64 = rfc_minimum_window;

/// Tunable congestion-control limits. Embedders opt into aggressive values
/// explicitly (e.g. libp2p gossip workloads on uncongested paths).
pub const CcOptions = struct {
    initial_window: u64 = rfc_initial_window,
    minimum_window: u64 = rfc_minimum_window,

    pub const aggressive: CcOptions = .{
        .initial_window = aggressive_initial_window,
        .minimum_window = aggressive_minimum_window,
    };
};

pub const CcState = enum {
    slow_start,
    congestion_avoidance,
    recovery,
};

/// New Reno congestion controller.
pub const NewReno = struct {
    /// Congestion window in bytes (RFC 9002 §7.2 default).
    cwnd: u64 = rfc_initial_window,
    /// Post-loss floor (RFC 9002 §7.6.3 default; override via `CcOptions`).
    min_window: u64 = minimum_window,
    /// Slow start threshold.
    ssthresh: u64 = max_cwnd,
    /// Bytes in flight.
    bytes_in_flight: u64 = 0,
    /// State.
    state: CcState = .slow_start,
    /// Number of bytes ACKed since entering congestion avoidance.
    bytes_acked_ca: u64 = 0,
    /// Largest ACKed packet number in the current recovery period.
    end_of_recovery: ?u64 = null,
    /// Diagnostics (not used in CC math): total congestion-reduction events and
    /// cumulative bytes ACKed, for the backpressure CC trace.
    congestion_events: u64 = 0,
    total_bytes_acked: u64 = 0,

    pub fn init() NewReno {
        return .{};
    }

    pub fn initWithOptions(opts: CcOptions) NewReno {
        return .{ .cwnd = opts.initial_window, .min_window = opts.minimum_window };
    }

    /// Called when packets are acknowledged.
    pub fn onAck(self: *NewReno, bytes_acked: u64, largest_acked_pn: u64) void {
        self.total_bytes_acked +|= bytes_acked;
        self.bytes_in_flight -|= bytes_acked;

        if (self.state == .recovery) {
            // RFC 9002 §7.3.2: exit recovery only when an ACK covers a packet
            // sent *after* the recovery period began. Exiting on the first ACK
            // (and clearing `end_of_recovery`) defeats the once-per-flight loss
            // gate in `onLoss`, letting one congestion episode cut cwnd many
            // times to the floor. See Cubic.onAck for the full rationale.
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
            }
        } else if (self.state == .congestion_avoidance) {
            // Increase cwnd by MSS²/cwnd for each byte ACKed
            self.bytes_acked_ca += bytes_acked;
            while (self.bytes_acked_ca >= self.cwnd) {
                self.bytes_acked_ca -= self.cwnd;
                self.cwnd = @min(self.cwnd + mss, max_cwnd);
            }
        }
    }

    /// Called on packet loss.
    pub fn onLoss(self: *NewReno, largest_lost_pn: u64) void {
        // Only react to loss once per flight (RFC 9002 §7.3.2)
        if (self.end_of_recovery) |eor| {
            if (largest_lost_pn <= eor) return;
        }

        self.end_of_recovery = largest_lost_pn;
        self.ssthresh = @max(self.cwnd / 2, self.min_window);
        self.cwnd = self.ssthresh;
        self.bytes_acked_ca = 0;
        self.state = .recovery;
        self.congestion_events += 1;
    }

    /// Called when persistent congestion is detected (RFC 9002 §7.6.3).
    /// Collapses cwnd to the minimum window and re-enters slow start so the
    /// sender does not continue to overload an apparently dead path.
    /// Bytes-in-flight is left untouched — outstanding packets remain in
    /// flight until they are acked, lost, or discarded.
    pub fn onPersistentCongestion(self: *NewReno) void {
        self.cwnd = self.min_window;
        self.state = .slow_start;
        self.bytes_acked_ca = 0;
        self.end_of_recovery = null;
    }

    /// ECN-CE feedback or other peer-signalled congestion (RFC 9002 §B.4 /
    /// RFC 9000 §13.4).  Equivalent to a packet-loss congestion event: halve
    /// cwnd and enter recovery, gated by `end_of_recovery` so we don't react
    /// twice within the same RTT.
    pub fn onCongestionEvent(self: *NewReno, largest_acked_pn: u64) void {
        self.onLoss(largest_acked_pn);
    }

    /// Called when a packet is sent.
    pub fn onPacketSent(self: *NewReno, bytes: u64) void {
        self.bytes_in_flight +|= bytes;
    }

    /// Returns the send credit (bytes allowed to be in flight).
    pub fn sendCredit(self: *const NewReno) u64 {
        return self.cwnd -| self.bytes_in_flight;
    }

    /// True if we may send more data (sender-side congestion check).
    pub fn canSend(self: *const NewReno, packet_size: u64) bool {
        return self.bytes_in_flight + packet_size <= self.cwnd;
    }
};

/// Tagged union wrapping available congestion controllers.
/// All variants expose the same interface so callers use `cc.onAck(...)` etc.
pub const CongestionController = union(enum) {
    new_reno: NewReno,
    cubic: @import("cubic.zig").Cubic,

    pub fn init(comptime tag: std.meta.Tag(CongestionController)) CongestionController {
        return initWithOptions(tag, .{});
    }

    pub fn initWithOptions(comptime tag: std.meta.Tag(CongestionController), opts: CcOptions) CongestionController {
        return switch (tag) {
            .new_reno => .{ .new_reno = NewReno.initWithOptions(opts) },
            .cubic => .{ .cubic = @import("cubic.zig").Cubic.initWithOptions(opts) },
        };
    }

    /// Aggressive CC profile for libp2p gossip workloads.
    pub fn initAggressive(comptime tag: std.meta.Tag(CongestionController)) CongestionController {
        return initWithOptions(tag, CcOptions.aggressive);
    }

    pub fn onAck(self: *CongestionController, bytes_acked: u64, largest_acked_pn: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.onAck(bytes_acked, largest_acked_pn),
        }
    }

    pub fn onLoss(self: *CongestionController, largest_lost_pn: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.onLoss(largest_lost_pn),
        }
    }

    pub fn onPersistentCongestion(self: *CongestionController) void {
        switch (self.*) {
            inline else => |*cc| cc.onPersistentCongestion(),
        }
    }

    pub fn onCongestionEvent(self: *CongestionController, largest_acked_pn: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.onCongestionEvent(largest_acked_pn),
        }
    }

    pub fn onPacketSent(self: *CongestionController, bytes: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.onPacketSent(bytes),
        }
    }

    pub fn sendCredit(self: *const CongestionController) u64 {
        switch (self.*) {
            inline else => |*cc| return cc.sendCredit(),
        }
    }

    pub fn canSend(self: *const CongestionController, packet_size: u64) bool {
        switch (self.*) {
            inline else => |*cc| return cc.canSend(packet_size),
        }
    }

    pub fn getBytesInFlight(self: *const CongestionController) u64 {
        switch (self.*) {
            inline else => |cc| return cc.bytes_in_flight,
        }
    }

    /// Current congestion window in bytes (used by the pacer).
    pub fn getCwnd(self: *const CongestionController) u64 {
        switch (self.*) {
            inline else => |cc| return cc.cwnd,
        }
    }

    /// Diagnostics accessors (backpressure CC trace).
    pub fn getSsthresh(self: *const CongestionController) u64 {
        switch (self.*) {
            inline else => |cc| return cc.ssthresh,
        }
    }

    pub fn getState(self: *const CongestionController) CcState {
        switch (self.*) {
            inline else => |cc| return cc.state,
        }
    }

    pub fn getCongestionEvents(self: *const CongestionController) u64 {
        switch (self.*) {
            .new_reno => |cc| return cc.congestion_events,
            .cubic => |cc| return cc.congestion_events,
        }
    }

    pub fn getTotalBytesAcked(self: *const CongestionController) u64 {
        switch (self.*) {
            .new_reno => |cc| return cc.total_bytes_acked,
            .cubic => |cc| return cc.total_bytes_acked,
        }
    }

    pub fn setBytesInFlight(self: *CongestionController, val: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.bytes_in_flight = val,
        }
    }

    pub fn subBytesInFlight(self: *CongestionController, val: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.bytes_in_flight -|= val,
        }
    }
};

test "new_reno: slow start growth" {
    const testing = std.testing;
    var cc = NewReno.init();
    try testing.expectEqual(CcState.slow_start, cc.state);
    const initial_cwnd = cc.cwnd;

    cc.onPacketSent(mss);
    cc.onAck(mss, 1);
    // In slow start, cwnd should grow by bytes_acked
    try testing.expectEqual(initial_cwnd + mss, cc.cwnd);
}

test "new_reno: loss triggers recovery" {
    const testing = std.testing;
    var cc = NewReno.init();
    cc.cwnd = 40 * mss; // well above the minimum-window floor so halving is visible
    cc.bytes_in_flight = 20 * mss;

    cc.onLoss(5);
    try testing.expectEqual(CcState.recovery, cc.state);
    try testing.expectEqual(@as(u64, 20 * mss), cc.ssthresh);
    try testing.expectEqual(@as(u64, 20 * mss), cc.cwnd);
}

test "new_reno: loss does not collapse below minimum window" {
    const testing = std.testing;
    var cc = NewReno.initWithOptions(CcOptions.aggressive);
    cc.cwnd = 12 * mss;
    // Several back-to-back loss events (distinct, increasing PNs) must not pin
    // cwnd below the aggressive floor.
    var pn: u64 = 1;
    while (pn < 8) : (pn += 1) cc.onLoss(pn);
    try testing.expectEqual(aggressive_minimum_window, cc.cwnd);
    try testing.expect(cc.cwnd >= aggressive_minimum_window);
}

test "new_reno: congestion avoidance" {
    const testing = std.testing;
    var cc = NewReno.init();
    cc.ssthresh = 10 * mss;
    cc.cwnd = 10 * mss;
    cc.state = .congestion_avoidance;

    const initial_cwnd = cc.cwnd;
    // ACK a full cwnd worth of bytes → cwnd increases by 1 MSS
    cc.onAck(cc.cwnd, 1);
    try testing.expectEqual(initial_cwnd + mss, cc.cwnd);
}

test "new_reno: can_send check" {
    const testing = std.testing;
    var cc = NewReno.init();
    cc.cwnd = 2 * mss;
    cc.bytes_in_flight = 2 * mss;

    try testing.expect(!cc.canSend(1));
    cc.onAck(mss, 1);
    try testing.expect(cc.canSend(mss));
}

test "new_reno: persistent congestion collapses to minimum window" {
    const testing = std.testing;
    var cc = NewReno.init();
    cc.cwnd = 100 * mss;
    cc.state = .congestion_avoidance;
    cc.bytes_acked_ca = 12345;

    cc.onPersistentCongestion();
    try testing.expectEqual(minimum_window, cc.cwnd);
    try testing.expectEqual(CcState.slow_start, cc.state);
    try testing.expectEqual(@as(u64, 0), cc.bytes_acked_ca);
}

test "new_reno: onCongestionEvent equivalent to onLoss" {
    const testing = std.testing;
    var a = NewReno.init();
    var b = NewReno.init();
    a.cwnd = 20 * mss;
    b.cwnd = 20 * mss;
    a.bytes_in_flight = 10 * mss;
    b.bytes_in_flight = 10 * mss;
    a.onLoss(42);
    b.onCongestionEvent(42);
    try testing.expectEqual(a.cwnd, b.cwnd);
    try testing.expectEqual(a.ssthresh, b.ssthresh);
    try testing.expectEqual(a.state, b.state);
}

test "congestion_controller: tagged union dispatches correctly" {
    const testing = std.testing;

    // NewReno variant
    var nr = CongestionController.init(.new_reno);
    nr.onPacketSent(mss);
    try testing.expectEqual(@as(u64, mss), nr.getBytesInFlight());
    try testing.expect(nr.canSend(mss));
    nr.onAck(mss, 1);
    try testing.expectEqual(@as(u64, 0), nr.getBytesInFlight());

    // CUBIC variant
    var cubic = CongestionController.init(.cubic);
    cubic.onPacketSent(mss);
    try testing.expectEqual(@as(u64, mss), cubic.getBytesInFlight());
    try testing.expect(cubic.canSend(mss));
    cubic.onLoss(1);
    // After loss, CUBIC sets cwnd = cwnd × β (0.7).
    try testing.expect(cubic.canSend(mss));

    // Persistent congestion collapses both variants to the minimum window.
    // bytes_in_flight may still be non-zero from earlier; assert by reading
    // the cwnd directly via sendCredit() bound.
    nr.setBytesInFlight(0);
    cubic.setBytesInFlight(0);
    nr.onPersistentCongestion();
    cubic.onPersistentCongestion();
    try testing.expectEqual(minimum_window, nr.sendCredit());
    try testing.expectEqual(minimum_window, cubic.sendCredit());
}
