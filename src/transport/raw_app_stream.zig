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
    /// Contiguous bytes that have been reassembled past `next_offset` but whose
    /// splice into the embedder-visible `buf` was deferred because this drive's
    /// per-drive delivery budget (`max_raw_app_delivery_per_drive`) was already
    /// spent. These are already in order (offset == the running boundary at the
    /// time they were deferred) so `resumeDeferred` drains them FIFO with no scan
    /// on the next drive. Keeping them out of `buf` bounds how many freshly
    /// reassembled bytes one heavy conn hands the embedder per drive — the
    /// recv-side analogue of the per-drive STREAM **send** budget. The QUIC layer
    /// has still received + ACKed every byte (flow control is honoured); only the
    /// app-facing hand-off is paced.
    deferred: std.ArrayListUnmanaged(u8) = .empty,
    /// True once a STREAM frame with FIN=true has been seen on this stream.
    /// NOTE: the FIN bit can arrive (on a small trailing frame) before the
    /// earlier bulk data has been reassembled, so `fin_received` alone does
    /// NOT mean the stream is complete — use `fullyReceived`.
    fin_received: bool = false,
    /// Final stream size, recorded from the FIN frame (`offset + len`). Only
    /// meaningful once `fin_received` is true.
    fin_offset: u64 = 0,
    /// True once the peer reset this stream with a RESET_STREAM frame
    /// (RFC 9000 §19.4); `reset_error_code` carries the app error code.
    reset_received: bool = false,
    reset_error_code: u64 = 0,

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
        self.deferred.deinit(allocator);
        self.buf.deinit(allocator);
        self.* = .{};
    }
};

/// Per-drive cap on how many freshly reassembled bytes are spliced into one
/// stream's embedder-visible `buf`. Bytes beyond this stay in the slot's
/// `deferred` holding buffer and are delivered on the next drive (see
/// `resumeDeferred`). This bounds the synchronous post-drive work the embedder
/// does for a single heavy stream (parsing a multi-MB reqresp block) so one conn
/// receiving a large response cannot monopolize the shared drive thread — the
/// recv-side analogue of `max_sends_per_drive`. Sized to ~one large block's
/// worth split across a handful of drives: large enough that small/normal
/// responses (gossip, identify, status) always complete in a single drive, small
/// enough that a 3–32 MB blocks_by_range response is paced over several drives.
/// The QUIC layer still decrypts, parses, ACKs, and flow-control-credits EVERY
/// received packet in the drive — only the app hand-off is paced, so the peer's
/// MAX_DATA / MAX_STREAM_DATA grants are never withheld (no send-window
/// starvation; that was the failure mode of a blanket recv time-cap).
pub const max_raw_app_delivery_per_drive: usize = 512 * 1024;

/// A `DeliveryBudget` is shared across every `receiveFrame` call in one drive
/// (all streams on the conn) and reset once at drive entry, mirroring how
/// `ConnState.sends_this_drive` shares one `max_sends_per_drive` allotment.
pub const DeliveryBudget = struct {
    spent: usize = 0,
    pub fn remaining(self: *const DeliveryBudget) usize {
        return max_raw_app_delivery_per_drive -| self.spent;
    }
};

/// The running contiguous-received boundary: everything in `[0, recvBoundary)`
/// has arrived (split between the embedder-visible `buf` and the not-yet-handed
/// `deferred` tail).
fn recvBoundary(slot: *const RawAppStreamSlot) u64 {
    return slot.next_offset + @as(u64, @intCast(slot.deferred.items.len));
}

/// Append `bytes` to the contiguous region, spending the shared per-drive
/// delivery budget. Up to `budget.remaining()` bytes go straight into the
/// embedder-visible `buf` (advancing `next_offset`); any overflow is parked in
/// `deferred` (which always sits immediately after `buf`) for a later drive.
/// When `budget` is null (retransmit/loss paths, processPendingWork) all bytes
/// are delivered — those paths are already bounded elsewhere and must not stall.
fn deliverContiguous(
    allocator: std.mem.Allocator,
    slot: *RawAppStreamSlot,
    bytes: []const u8,
    budget: ?*DeliveryBudget,
) std.mem.Allocator.Error!void {
    if (bytes.len == 0) return;
    // Bytes already deferred must stay ordered before any newly-arriving tail,
    // so once a stream has a deferred backlog everything new is appended there.
    if (slot.deferred.items.len > 0) {
        try slot.deferred.appendSlice(allocator, bytes);
        return;
    }
    const room: usize = if (budget) |b| b.remaining() else bytes.len;
    const take = @min(room, bytes.len);
    if (take > 0) {
        try slot.buf.appendSlice(allocator, bytes[0..take]);
        slot.next_offset += @as(u64, @intCast(take));
        if (budget) |b| b.spent += take;
    }
    if (take < bytes.len) {
        try slot.deferred.appendSlice(allocator, bytes[take..]);
    }
}

/// Splice any buffered out-of-order frames that have become contiguous with the
/// running receive boundary, spending the per-drive budget as they land.
fn flushPending(
    allocator: std.mem.Allocator,
    slot: *RawAppStreamSlot,
    budget: ?*DeliveryBudget,
) std.mem.Allocator.Error!void {
    while (true) {
        const boundary = recvBoundary(slot);
        var found: ?usize = null;
        for (slot.out_of_order.items, 0..) |p, i| {
            if (p.off == boundary) {
                found = i;
                break;
            }
        }
        const idx = found orelse return;
        var pending = slot.out_of_order.swapRemove(idx);
        defer pending.deinit(allocator);
        try deliverContiguous(allocator, slot, pending.data.items, budget);
    }
}

/// Append stream bytes and splice any buffered gaps that become contiguous.
/// `budget` is the conn's shared per-drive delivery allotment (null = deliver
/// everything, for paths that are bounded elsewhere). See
/// `max_raw_app_delivery_per_drive`.
pub fn receiveFrame(
    allocator: std.mem.Allocator,
    slot: *RawAppStreamSlot,
    o: u64,
    d: []const u8,
    budget: ?*DeliveryBudget,
) std.mem.Allocator.Error!void {
    const frame_end = o + @as(u64, @intCast(d.len));
    const boundary = recvBoundary(slot);
    if (frame_end <= boundary) return;

    if (o > boundary) {
        for (slot.out_of_order.items) |p| {
            if (p.off == o) return;
        }
        var copy = std.ArrayListUnmanaged(u8).empty;
        try copy.appendSlice(allocator, d);
        try slot.out_of_order.append(allocator, .{ .off = o, .data = copy });
        try flushPending(allocator, slot, budget);
        return;
    }

    const start: usize = @intCast(boundary - o);
    try deliverContiguous(allocator, slot, d[start..], budget);
    try flushPending(allocator, slot, budget);
}

/// Drain bytes parked in `deferred` (from a previous drive that hit the delivery
/// budget) into the embedder-visible `buf`, spending this drive's budget. Call
/// once per drive — at drive entry, before the feedPacket recv loop — for every
/// active raw-app slot, so a heavy stream's backlog bleeds out over successive
/// drives instead of all at once. Returns true if any stream still has a
/// backlog (caller may keep draining on subsequent drives).
pub fn resumeDeferred(
    allocator: std.mem.Allocator,
    slot: *RawAppStreamSlot,
    budget: *DeliveryBudget,
) std.mem.Allocator.Error!void {
    if (slot.deferred.items.len == 0) return;
    const room = budget.remaining();
    if (room == 0) return;
    const take = @min(room, slot.deferred.items.len);
    try slot.buf.appendSlice(allocator, slot.deferred.items[0..take]);
    slot.next_offset += @as(u64, @intCast(take));
    budget.spent += take;
    if (take == slot.deferred.items.len) {
        slot.deferred.clearRetainingCapacity();
        // Backlog cleared — newly-contiguous out-of-order frames (if any) can
        // now splice directly into `buf` again.
        try flushPending(allocator, slot, budget);
    } else {
        // Shift the consumed prefix out; remaining bytes start at next_offset.
        const remaining_n = slot.deferred.items.len - take;
        std.mem.copyForwards(u8, slot.deferred.items[0..remaining_n], slot.deferred.items[take..]);
        slot.deferred.shrinkRetainingCapacity(remaining_n);
    }
}

test "receiveFrame: contiguous append and duplicate retransmit" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 4 };
    defer slot.deinit(allocator);

    try receiveFrame(allocator, &slot, 0, "hello", null);
    try std.testing.expectEqualStrings("hello", slot.buf.items);
    try std.testing.expectEqual(@as(u64, 5), slot.next_offset);

    try receiveFrame(allocator, &slot, 5, "!", null);
    try std.testing.expectEqualStrings("hello!", slot.buf.items);
    try std.testing.expectEqual(@as(u64, 6), slot.next_offset);

    try receiveFrame(allocator, &slot, 0, "hello!", null);
    try std.testing.expectEqualStrings("hello!", slot.buf.items);
    try std.testing.expectEqual(@as(u64, 6), slot.next_offset);
}

test "receiveFrame: out-of-order gap fill (libp2p reordering)" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 8 };
    defer slot.deinit(allocator);

    try receiveFrame(allocator, &slot, 0, "abc", null);
    try receiveFrame(allocator, &slot, 6, "ghi", null);
    try std.testing.expectEqual(@as(u64, 3), slot.next_offset);
    try std.testing.expectEqualStrings("abc", slot.buf.items);

    try receiveFrame(allocator, &slot, 3, "def", null);
    try std.testing.expectEqualStrings("abcdefghi", slot.buf.items);
    try std.testing.expectEqual(@as(u64, 9), slot.next_offset);

    try receiveFrame(allocator, &slot, 7, "hij", null);
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

    try receiveFrame(allocator, &slot, 0, "abc", null);
    try std.testing.expect(!slot.fullyReceived()); // 3/6 bytes contiguous

    try receiveFrame(allocator, &slot, 3, "def", null);
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

    try receiveFrame(allocator, &slot, 5, "tail", null);
    try std.testing.expectEqual(@as(u64, 0), slot.next_offset);
    try std.testing.expectEqual(@as(usize, 1), slot.out_of_order.items.len);

    try receiveFrame(allocator, &slot, 5, "tail", null);
    try std.testing.expectEqual(@as(usize, 1), slot.out_of_order.items.len);
}

test "delivery budget: contiguous bytes past the per-drive cap are deferred, not lost" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 4 };
    defer slot.deinit(allocator);

    // One drive's worth of budget = the per-drive cap. Feed 1.5× the cap of
    // contiguous bytes in a single drive: exactly `cap` reaches the visible buf,
    // the rest is parked in `deferred` (still received at the QUIC layer — the
    // boundary advanced — so an ACK for these frames is honest).
    const cap = max_raw_app_delivery_per_drive;
    const big = try allocator.alloc(u8, cap + cap / 2);
    defer allocator.free(big);
    for (big, 0..) |*b, i| b.* = @intCast(i % 251);

    var budget: DeliveryBudget = .{};
    try receiveFrame(allocator, &slot, 0, big, &budget);
    try std.testing.expectEqual(cap, slot.buf.items.len); // visible == budget
    try std.testing.expectEqual(@as(u64, cap), slot.next_offset);
    try std.testing.expectEqual(cap / 2, slot.deferred.items.len); // rest deferred
    try std.testing.expectEqual(cap + cap / 2, recvBoundary(&slot)); // all received

    // Next drive: a fresh budget drains the deferred backlog into the visible buf.
    var budget2: DeliveryBudget = .{};
    try resumeDeferred(allocator, &slot, &budget2);
    try std.testing.expectEqual(cap + cap / 2, slot.buf.items.len);
    try std.testing.expectEqual(@as(usize, 0), slot.deferred.items.len);
    try std.testing.expectEqualSlices(u8, big, slot.buf.items);
}

test "delivery budget: large payload paced over several drives reassembles intact + completes only when fully visible" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 4 };
    defer slot.deinit(allocator);

    const total: usize = 3 * 1024 * 1024; // ~one block
    const src = try allocator.alloc(u8, total);
    defer allocator.free(src);
    for (src, 0..) |*b, i| b.* = @intCast((i * 7 + 13) % 251);

    // Frames arrive 1100 bytes at a time; the FIN rides the last frame.
    const frame_len: usize = 1100;
    var off: usize = 0;
    var drives: usize = 0;
    // Each "drive": reset budget + resume backlog, then feed frames until the
    // budget is spent (so a heavy stream spills into `deferred`), bounded so the
    // test can't spin forever.
    while ((slot.next_offset < total or slot.deferred.items.len > 0) and drives < 10_000) : (drives += 1) {
        var budget: DeliveryBudget = .{};
        try resumeDeferred(allocator, &slot, &budget);
        const visible_before = slot.buf.items.len;
        while (off < total and budget.remaining() > 0) {
            const end = @min(off + frame_len, total);
            const fin = end == total;
            try receiveFrame(allocator, &slot, off, src[off..end], &budget);
            if (fin) {
                slot.fin_received = true;
                slot.fin_offset = end;
            }
            off = end;
        }
        // INVARIANT: no single drive hands the embedder more than the per-drive
        // cap (plus at most one straddling frame).
        const delivered = slot.buf.items.len - visible_before;
        try std.testing.expect(delivered <= max_raw_app_delivery_per_drive + frame_len);
    }

    // Pacing must take more than one drive for a 3 MB payload at a 512 KiB cap.
    try std.testing.expect(drives > 1);
    try std.testing.expect(slot.fullyReceived());
    try std.testing.expectEqual(total, slot.buf.items.len);
    try std.testing.expectEqualSlices(u8, src, slot.buf.items);
}

test "delivery budget: null budget delivers everything (unbounded loss/retransmit path)" {
    const allocator = std.testing.allocator;
    var slot: RawAppStreamSlot = .{ .active = true, .stream_id = 4 };
    defer slot.deinit(allocator);

    const big = try allocator.alloc(u8, max_raw_app_delivery_per_drive * 3);
    defer allocator.free(big);
    @memset(big, 0xCD);

    try receiveFrame(allocator, &slot, 0, big, null);
    try std.testing.expectEqual(big.len, slot.buf.items.len);
    try std.testing.expectEqual(@as(usize, 0), slot.deferred.items.len);
}
