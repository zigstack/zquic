//! Path MTU limits and DPLPMTUD state (RFC 9000 §14, RFC 8899).
//!
//! Clamps configured max UDP payload, derives STREAM chunk sizes, and tracks
//! a simplified PLPMTUD probe state machine for raising/lowering `plpmtu`.

const std = @import("std");
const types = @import("../types.zig");

/// Conservative overhead below `max_udp_payload` for 1-RTT short header + STREAM + AEAD tag.
const quic_stream_overhead: usize = 150;

/// Minimum spacing between probe attempts (ms).
pub const probe_interval_ms: i64 = 1_000;

/// Probe size step when searching upward (bytes).
pub const probe_step: u16 = 256;

/// Consecutive probe losses before black-hole recovery (RFC 8899 §5.2).
pub const black_hole_loss_threshold: u8 = 3;

/// Cap on per-chunk app data so fixed stack buffers in `io.zig` stay bounded.
pub const max_app_stream_chunk_cap: usize = types.max_datagram_size - 64;

/// Clamp user/configured max UDP payload to RFC 9000 §14.1 minimum and RFC max UDP payload.
pub fn clampMaxUdpPayload(requested: u16) u16 {
    const lo: u16 = @intCast(types.min_initial_mtu);
    const hi: u16 = @truncate(types.max_udp_payload_size);
    return std.math.clamp(requested, lo, hi);
}

/// Largest HTTP/0.9 or HTTP/3 DATA chunk (bytes of file/content) per QUIC STREAM frame.
pub fn appStreamChunkBytes(max_udp_payload: u16) usize {
    const up = @as(usize, max_udp_payload);
    const raw = @max(400, up -| quic_stream_overhead);
    return @min(raw, max_app_stream_chunk_cap);
}

/// Result for initializing `ConnState` path fields from optional config.
pub fn initFromConfig(max_udp_payload_opt: ?u16) struct { max_udp_payload: u16, app_stream_chunk: usize } {
    const requested: u16 = max_udp_payload_opt orelse @as(u16, @truncate(types.max_datagram_size));
    const max_udp_payload = clampMaxUdpPayload(requested);
    return .{
        .max_udp_payload = max_udp_payload,
        .app_stream_chunk = appStreamChunkBytes(max_udp_payload),
    };
}

/// RFC 8899 PLPMTUD state for one QUIC path.
pub const PlPmtuState = struct {
    plpmtu: u16,
    search_high: u16,
    search_low: u16,
    probe_size: u16 = 0,
    probing: bool = false,
    probe_pn: ?u64 = null,
    consecutive_losses: u8 = 0,
    last_probe_ms: i64 = 0,
    black_hole: bool = false,

    pub fn init(max_udp_payload: u16) PlPmtuState {
        const clamped = clampMaxUdpPayload(max_udp_payload);
        return .{
            .plpmtu = clamped,
            .search_high = clamped,
            .search_low = @intCast(types.min_initial_mtu),
        };
    }

    pub fn effectiveMtu(self: *const PlPmtuState) u16 {
        return self.plpmtu;
    }

    pub fn appStreamChunk(self: *const PlPmtuState) usize {
        return appStreamChunkBytes(self.plpmtu);
    }

    /// Clamp `search_high` / `plpmtu` when the peer advertises a lower limit.
    pub fn applyPeerMax(self: *PlPmtuState, peer_max: u64) void {
        const peer = clampMaxUdpPayload(@intCast(@min(peer_max, types.max_udp_payload_size)));
        if (peer < self.search_high) self.search_high = peer;
        if (peer < self.plpmtu) {
            self.plpmtu = peer;
            self.black_hole = true;
        }
    }

    /// Returns the next probe payload size, or null if probing should wait.
    pub fn maybeProbeSize(self: *PlPmtuState, now_ms: i64) ?u16 {
        if (self.probing or self.black_hole) return null;
        if (self.plpmtu >= self.search_high) return null;
        if (now_ms - self.last_probe_ms < probe_interval_ms) return null;
        const next = @min(self.plpmtu + probe_step, self.search_high);
        if (next <= self.plpmtu) return null;
        return next;
    }

    pub fn beginProbe(self: *PlPmtuState, size: u16, pn: u64, now_ms: i64) void {
        self.probe_size = size;
        self.probe_pn = pn;
        self.probing = true;
        self.last_probe_ms = now_ms;
    }

    pub fn onProbeAcked(self: *PlPmtuState, pn: u64) void {
        if (!self.probing or self.probe_pn != pn) return;
        self.plpmtu = self.probe_size;
        self.probing = false;
        self.probe_pn = null;
        self.consecutive_losses = 0;
    }

    pub fn onProbeLost(self: *PlPmtuState) void {
        if (!self.probing) return;
        self.probing = false;
        self.probe_pn = null;
        if (self.probe_size > self.search_low + 1) {
            self.search_high = self.probe_size - 1;
        }
        self.consecutive_losses += 1;
        if (self.consecutive_losses >= black_hole_loss_threshold) {
            self.black_hole = true;
            self.plpmtu = @max(@as(u16, @intCast(types.min_initial_mtu)), self.plpmtu / 2);
        }
    }
};

test "path_mtu: clamp and chunk" {
    const t = std.testing;
    try t.expectEqual(@as(u16, 1200), clampMaxUdpPayload(1000));
    try t.expectEqual(@as(u16, 1500), clampMaxUdpPayload(1500));
    try t.expect(appStreamChunkBytes(1500) >= 1300);
    try t.expectEqual(@as(usize, 1050), appStreamChunkBytes(1200));
    try t.expect(appStreamChunkBytes(65527) <= max_app_stream_chunk_cap);
}

test "path_mtu: plpmtu probe raise and black-hole" {
    var st = PlPmtuState.init(1200);
    st.search_high = 1500;
    const size = st.maybeProbeSize(5000).?;
    try std.testing.expect(size > 1200);
    st.beginProbe(size, 42, 5000);
    st.onProbeAcked(42);
    try std.testing.expectEqual(size, st.plpmtu);
    try std.testing.expect(!st.probing);

    st.beginProbe(1400, 43, 7000);
    st.onProbeLost();
    st.beginProbe(1400, 44, 8000);
    st.onProbeLost();
    st.beginProbe(1400, 45, 9000);
    st.onProbeLost();
    try std.testing.expect(st.black_hole);
    try std.testing.expect(st.plpmtu <= 1200);
}
