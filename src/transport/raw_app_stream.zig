//! Opaque application-stream reassembly for libp2p-style embedders.
//!
//! When `raw_application_streams` is enabled, incoming STREAM frames are
//! buffered here instead of being parsed as HTTP/0.9 or HTTP/3.

const std = @import("std");

/// One out-of-order STREAM chunk waiting until `next_offset` reaches `off`.
const RawAppPendingFrame = struct {
    off: u64,
    data: std.ArrayListUnmanaged(u8) = .empty,

    fn deinit(self: *RawAppPendingFrame, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }
};

/// Receive buffer for one QUIC stream when raw application streams are enabled.
pub const RawAppStreamSlot = struct {
    active: bool = false,
    stream_id: u64 = 0,
    /// Next contiguous byte offset expected; bytes [0..next_offset) are in `buf`.
    next_offset: u64 = 0,
    buf: std.ArrayListUnmanaged(u8) = .empty,
    /// STREAM frames that arrived ahead of `next_offset` (UDP reordering).
    out_of_order: std.ArrayListUnmanaged(RawAppPendingFrame) = .empty,
    /// True once a STREAM frame with FIN=true has been seen on this stream.
    /// NOTE: the FIN bit can arrive (on a small trailing frame) before the
    /// earlier bulk data has been reassembled, so `fin_received` alone does
    /// NOT mean the stream is complete — use `fullyReceived`.
    fin_received: bool = false,
    /// Final stream size, recorded from the FIN frame (`offset + len`). Only
    /// meaningful once `fin_received` is true.
    fin_offset: u64 = 0,

    /// True only when the peer has FIN'd **and** all bytes up to the final
    /// size have been contiguously reassembled into `buf`. This is the signal
    /// embedders must use to decide "the response is complete" — `fin_received`
    /// races ahead of the data because a trailing 0-byte FIN frame (the libp2p
    /// reqresp half-close) can be processed before the cwnd-queued payload.
    pub fn fullyReceived(self: *const RawAppStreamSlot) bool {
        return self.fin_received and self.next_offset >= self.fin_offset;
    }

    pub fn deinit(self: *RawAppStreamSlot, allocator: std.mem.Allocator) void {
        for (self.out_of_order.items) |*p| {
            p.deinit(allocator);
        }
        self.out_of_order.deinit(allocator);
        self.buf.deinit(allocator);
        self.* = .{};
    }
};

fn flushPending(allocator: std.mem.Allocator, slot: *RawAppStreamSlot) std.mem.Allocator.Error!void {
    while (true) {
        var found: ?usize = null;
        for (slot.out_of_order.items, 0..) |p, i| {
            if (p.off == slot.next_offset) {
                found = i;
                break;
            }
        }
        const idx = found orelse return;
        var pending = slot.out_of_order.swapRemove(idx);
        defer pending.deinit(allocator);
        try slot.buf.appendSlice(allocator, pending.data.items);
        slot.next_offset += @as(u64, @intCast(pending.data.items.len));
    }
}

/// Append stream bytes and splice any buffered gaps that become contiguous.
pub fn receiveFrame(allocator: std.mem.Allocator, slot: *RawAppStreamSlot, o: u64, d: []const u8) std.mem.Allocator.Error!void {
    const frame_end = o + @as(u64, @intCast(d.len));
    if (frame_end <= slot.next_offset) return;

    if (o > slot.next_offset) {
        for (slot.out_of_order.items) |p| {
            if (p.off == o) return;
        }
        var copy = std.ArrayListUnmanaged(u8).empty;
        try copy.appendSlice(allocator, d);
        try slot.out_of_order.append(allocator, .{ .off = o, .data = copy });
        try flushPending(allocator, slot);
        return;
    }

    const start: usize = @intCast(slot.next_offset - o);
    try slot.buf.appendSlice(allocator, d[start..]);
    slot.next_offset = frame_end;
    try flushPending(allocator, slot);
}

test "receiveFrame: contiguous append and duplicate retransmit" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 4 };
    defer slot.deinit(allocator);

    try receiveFrame(allocator, &slot, 0, "hello");
    try std.testing.expectEqualStrings("hello", slot.buf.items);
    try std.testing.expectEqual(@as(u64, 5), slot.next_offset);

    try receiveFrame(allocator, &slot, 5, "!");
    try std.testing.expectEqualStrings("hello!", slot.buf.items);
    try std.testing.expectEqual(@as(u64, 6), slot.next_offset);

    try receiveFrame(allocator, &slot, 0, "hello!");
    try std.testing.expectEqualStrings("hello!", slot.buf.items);
    try std.testing.expectEqual(@as(u64, 6), slot.next_offset);
}

test "receiveFrame: out-of-order gap fill (libp2p reordering)" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 8 };
    defer slot.deinit(allocator);

    try receiveFrame(allocator, &slot, 0, "abc");
    try receiveFrame(allocator, &slot, 6, "ghi");
    try std.testing.expectEqual(@as(u64, 3), slot.next_offset);
    try std.testing.expectEqualStrings("abc", slot.buf.items);

    try receiveFrame(allocator, &slot, 3, "def");
    try std.testing.expectEqualStrings("abcdefghi", slot.buf.items);
    try std.testing.expectEqual(@as(u64, 9), slot.next_offset);

    try receiveFrame(allocator, &slot, 7, "hij");
    try std.testing.expectEqualStrings("abcdefghij", slot.buf.items);
    try std.testing.expectEqual(@as(u64, 10), slot.next_offset);
}

test "fullyReceived: FIN ahead of data is not complete until the gap fills" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 4 };
    defer slot.deinit(allocator);

    // Trailing FIN frame (offset 6, 0 bytes) arrives before the bulk payload —
    // the libp2p reqresp half-close racing ahead of cwnd-queued data. The
    // caller records fin_received + fin_offset (as io.zig does on the FIN bit).
    slot.fin_received = true;
    slot.fin_offset = 6;
    try std.testing.expect(!slot.fullyReceived()); // no data yet (next_offset=0)

    try receiveFrame(allocator, &slot, 0, "abc");
    try std.testing.expect(!slot.fullyReceived()); // 3/6 bytes contiguous

    try receiveFrame(allocator, &slot, 3, "def");
    try std.testing.expect(slot.fullyReceived()); // 6/6 — complete
}

test "fullyReceived: empty (0-byte) FIN is immediately complete" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 4 };
    defer slot.deinit(allocator);

    // Empty reqresp response: a 0-byte FIN at offset 0 (peer has no data).
    slot.fin_received = true;
    slot.fin_offset = 0;
    try std.testing.expect(slot.fullyReceived());
}

test "receiveFrame: duplicate out-of-order chunk is ignored" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 12 };
    defer slot.deinit(allocator);

    try receiveFrame(allocator, &slot, 5, "tail");
    try std.testing.expectEqual(@as(u64, 0), slot.next_offset);
    try std.testing.expectEqual(@as(usize, 1), slot.out_of_order.items.len);

    try receiveFrame(allocator, &slot, 5, "tail");
    try std.testing.expectEqual(@as(usize, 1), slot.out_of_order.items.len);
}
