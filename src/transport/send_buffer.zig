//! Per-stream send buffer (quinn `SendBuffer`-style, RFC 9000 §2).
//!
//! Holds unacked application bytes in offset-ordered segments.  Supports
//! partial-frame retransmit: a lost 4 KiB STREAM frame can be re-emitted as
//! narrower slices via `pollTransmit(max_len)` without pushing that work to
//! the embedder.

const std = @import("std");

pub const Range = struct {
    offset: u64,
    len: usize,
};

/// Byte range relative to the start of a segment's `data` buffer.
const RelRange = struct {
    off: usize,
    len: usize,
};

const Segment = struct {
    offset: u64,
    data: []u8,
    /// Bytes from the start of this segment that have been put on the wire and
    /// are not yet ACKed (includes in-flight and lost ranges).
    sent: usize = 0,
    /// Non-overlapping ACKed ranges relative to `offset` (quinn-style).
    acked_ranges: std.ArrayList(RelRange) = .empty,
};

pub const PollResult = struct {
    offset: u64,
    data: []const u8,
    fin: bool,
    /// True when this slice comes from a lost range (retransmit).
    retransmit: bool = false,
};

fn totalAckedBytes(ranges: []const RelRange) usize {
    var sum: usize = 0;
    for (ranges) |r| sum += r.len;
    return sum;
}

/// Contiguous ACK prefix from the segment start (0).  Zero when the first
/// acked range does not begin at 0 — gaps before it are still in flight.
fn contiguousAckedEnd(ranges: []const RelRange) usize {
    if (ranges.len == 0 or ranges[0].off != 0) return 0;
    return ranges[0].len;
}

fn mergeAckedRange(
    ranges: *std.ArrayList(RelRange),
    allocator: std.mem.Allocator,
    off: usize,
    len: usize,
) !usize {
    if (len == 0) return 0;
    const old_total = totalAckedBytes(ranges.items);
    const end = off + len;

    var new_off = off;
    var new_end = end;
    var i: usize = 0;
    while (i < ranges.items.len) {
        const r = ranges.items[i];
        const r_end = r.off + r.len;
        if (new_end <= r.off or new_off >= r_end) {
            i += 1;
            continue;
        }
        new_off = @min(new_off, r.off);
        new_end = @max(new_end, r_end);
        _ = ranges.orderedRemove(i);
    }
    try ranges.append(allocator, .{ .off = new_off, .len = new_end - new_off });

    std.mem.sort(RelRange, ranges.items, {}, struct {
        fn less(_: void, a: RelRange, b: RelRange) bool {
            return a.off < b.off;
        }
    }.less);

    i = 0;
    while (i + 1 < ranges.items.len) {
        const a = &ranges.items[i];
        const b = &ranges.items[i + 1];
        if (a.off + a.len >= b.off) {
            const merged_end = @max(a.off + a.len, b.off + b.len);
            a.len = merged_end - a.off;
            _ = ranges.orderedRemove(i + 1);
            continue;
        }
        i += 1;
    }

    return totalAckedBytes(ranges.items) - old_total;
}

pub const SendBuffer = struct {
    segments: std.ArrayList(Segment) = .empty,
    lost: std.ArrayList(Range) = .empty,
    /// Stream end offset when FIN was queued (exclusive).
    fin_at: ?u64 = null,
    fin_sent: bool = false,
    queued_bytes: usize = 0,

    pub fn deinit(self: *SendBuffer, allocator: std.mem.Allocator) void {
        for (self.segments.items) |*seg| {
            seg.acked_ranges.deinit(allocator);
            allocator.free(seg.data);
        }
        self.segments.deinit(allocator);
        self.lost.deinit(allocator);
        self.* = .{};
    }

    pub fn byteLen(self: *const SendBuffer) usize {
        return self.queued_bytes;
    }

    /// Append `data` at `offset`.  Coalesces with the tail segment when contiguous.
    pub fn append(
        self: *SendBuffer,
        allocator: std.mem.Allocator,
        offset: u64,
        data: []const u8,
        fin: bool,
    ) !void {
        if (data.len == 0 and !fin) return;
        if (data.len > 0) {
            if (self.segments.items.len > 0) {
                const last = &self.segments.items[self.segments.items.len - 1];
                const tail_end = last.offset + last.data.len;
                if (tail_end == offset) {
                    const new_len = last.data.len + data.len;
                    const grown = try allocator.realloc(last.data, new_len);
                    @memcpy(grown[last.data.len..][0..data.len], data);
                    last.data = grown;
                    self.queued_bytes += data.len;
                    if (fin) self.fin_at = offset + data.len;
                    return;
                }
            }
            const dup = try allocator.dupe(u8, data);
            try self.segments.append(allocator, .{ .offset = offset, .data = dup });
            self.queued_bytes += data.len;
        }
        if (fin) {
            self.fin_at = if (data.len > 0) offset + data.len else offset;
        }
    }

    fn pruneAcked(self: *SendBuffer, allocator: std.mem.Allocator) void {
        while (self.segments.items.len > 0) {
            const seg = &self.segments.items[0];
            if (contiguousAckedEnd(seg.acked_ranges.items) < seg.data.len) break;
            seg.acked_ranges.deinit(allocator);
            allocator.free(seg.data);
            _ = self.segments.orderedRemove(0);
        }
        if (self.segments.items.len == 0) {
            self.lost.clearRetainingCapacity();
            return;
        }
        const head = self.segments.items[0];
        const head_cont = contiguousAckedEnd(head.acked_ranges.items);
        var i: usize = 0;
        while (i < self.lost.items.len) {
            const r = self.lost.items[i];
            if (r.offset + r.len <= head.offset + head_cont) {
                _ = self.lost.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn mergeLost(self: *SendBuffer, allocator: std.mem.Allocator, offset: u64, len: usize) !void {
        if (len == 0) return;
        var new_off = offset;
        var new_end = offset + len;
        var i: usize = 0;
        while (i < self.lost.items.len) {
            const r = self.lost.items[i];
            const r_end = r.offset + r.len;
            if (new_end < r.offset or new_off > r_end) {
                i += 1;
                continue;
            }
            new_off = @min(new_off, r.offset);
            new_end = @max(new_end, r_end);
            _ = self.lost.orderedRemove(i);
        }
        try self.lost.append(allocator, .{ .offset = new_off, .len = @intCast(new_end - new_off) });
    }

    /// Mark `[offset, offset+len)` as ACKed by the peer.
    pub fn onAck(self: *SendBuffer, allocator: std.mem.Allocator, offset: u64, len: usize) void {
        if (len == 0) {
            if (self.fin_at == offset) self.fin_sent = false;
            self.fin_at = null;
            return;
        }
        const end = offset + len;
        var i: usize = 0;
        while (i < self.lost.items.len) {
            const r = self.lost.items[i];
            if (r.offset >= end or r.offset + r.len <= offset) {
                i += 1;
                continue;
            }
            if (r.offset >= offset and r.offset + r.len <= end) {
                _ = self.lost.orderedRemove(i);
                continue;
            }
            i += 1;
        }
        for (self.segments.items) |*seg| {
            const seg_end = seg.offset + seg.data.len;
            if (end <= seg.offset or offset >= seg_end) continue;
            const ix_start = @max(offset, seg.offset);
            const ix_end = @min(end, seg_end);
            const rel_off: usize = @intCast(ix_start - seg.offset);
            const rel_len: usize = @intCast(ix_end - ix_start);
            const delta = mergeAckedRange(&seg.acked_ranges, allocator, rel_off, rel_len) catch continue;
            self.queued_bytes -|= delta;
            const rel_end = rel_off + rel_len;
            if (rel_end > seg.sent) seg.sent = rel_end;
        }
        self.pruneAcked(allocator);
    }

    /// Mark `[offset, offset+len)` as lost — eligible for `pollTransmit`.
    pub fn onLoss(self: *SendBuffer, allocator: std.mem.Allocator, offset: u64, len: usize) !void {
        if (len == 0) return;
        const end = offset + len;
        var has_backing = false;
        for (self.segments.items) |seg| {
            const seg_end = seg.offset + seg.data.len;
            if (end > seg.offset and offset < seg_end) {
                has_backing = true;
                break;
            }
        }
        if (!has_backing) return;
        try self.mergeLost(allocator, offset, len);
        for (self.segments.items) |*seg| {
            const seg_end = seg.offset + seg.data.len;
            if (offset >= seg_end or end <= seg.offset) continue;
            const rel_start: usize = @intCast(@max(offset, seg.offset) - seg.offset);
            if (rel_start < seg.sent) seg.sent = rel_start;
        }
    }

    fn sliceFromSegment(seg: *const Segment, off: u64, max_len: usize) ?PollResult {
        if (off < seg.offset or off >= seg.offset + seg.data.len) return null;
        const rel: usize = @intCast(off - seg.offset);
        const avail = seg.data.len - rel;
        const n = @min(avail, max_len);
        const fin = if (seg.offset + seg.data.len == off + n)
            false // FIN handled separately via fin_at
        else
            false;
        return .{ .offset = off, .data = seg.data[rel .. rel + n], .fin = fin };
    }

    /// Next range to put on the wire (lost ranges first, then unsent tail).
    pub fn hasWork(self: *const SendBuffer) bool {
        if (self.lost.items.len > 0) return true;
        for (self.segments.items) |seg| {
            if (seg.sent < seg.data.len) return true;
        }
        if (self.fin_at != null and !self.fin_sent) return true;
        return false;
    }

    /// Next range to put on the wire (lost ranges first, then unsent tail).
    pub fn pollTransmit(self: *SendBuffer, max_len: usize) ?PollResult {
        if (max_len == 0) return null;

        if (self.lost.items.len > 0) {
            std.mem.sort(Range, self.lost.items, {}, struct {
                fn less(_: void, a: Range, b: Range) bool {
                    return a.offset < b.offset;
                }
            }.less);
            const r = self.lost.items[0];
            const n = @min(r.len, max_len);
            for (self.segments.items) |*seg| {
                if (r.offset >= seg.offset and r.offset < seg.offset + seg.data.len) {
                    const res = sliceFromSegment(seg, r.offset, n) orelse continue;
                    const fin = self.fin_at == r.offset + n;
                    return .{ .offset = res.offset, .data = res.data, .fin = fin, .retransmit = true };
                }
            }
            return null;
        }

        for (self.segments.items) |*seg| {
            const unsent_off = seg.offset + seg.sent;
            if (seg.sent >= seg.data.len) continue;
            const n = @min(seg.data.len - seg.sent, max_len);
            const fin = self.fin_at == unsent_off + n;
            return .{
                .offset = unsent_off,
                .data = seg.data[seg.sent .. seg.sent + n],
                .fin = fin,
                .retransmit = false,
            };
        }

        if (self.fin_at) |fa| {
            for (self.segments.items) |*seg| {
                if (seg.offset + seg.data.len == fa and seg.sent == seg.data.len) {
                    if (!self.fin_sent) {
                        return .{ .offset = fa, .data = &.{}, .fin = true, .retransmit = false };
                    }
                    break;
                }
            }
            if (self.segments.items.len == 0 and !self.fin_sent) {
                return .{ .offset = fa, .data = &.{}, .fin = true, .retransmit = false };
            }
        }
        return null;
    }

    /// Record that `poll` bytes were sent on the wire (awaiting ACK).
    pub fn onSent(self: *SendBuffer, offset: u64, len: usize) void {
        if (len == 0) {
            if (self.fin_at == offset) self.fin_sent = true;
            return;
        }
        for (self.segments.items) |*seg| {
            const seg_end = seg.offset + seg.data.len;
            if (offset >= seg_end or offset + len <= seg.offset) continue;
            const rel_end: usize = @intCast(offset + len - seg.offset);
            if (rel_end > seg.sent) seg.sent = rel_end;
        }
        if (self.fin_at) |fa| {
            if (offset + len >= fa) self.fin_sent = true;
        }
        if (self.lost.items.len > 0) {
            const end = offset + len;
            var r = &self.lost.items[0];
            if (r.offset == offset) {
                if (len >= r.len) {
                    _ = self.lost.orderedRemove(0);
                } else {
                    r.offset += len;
                    r.len -= len;
                }
            } else if (offset < r.offset and end > r.offset) {
                const overlap = end - r.offset;
                if (overlap >= r.len) {
                    _ = self.lost.orderedRemove(0);
                } else {
                    r.offset += overlap;
                    r.len -= overlap;
                }
            }
        }
    }
};

pub const stream_send_slot_max: usize = 512;

pub const StreamSendSlot = struct {
    active: bool = false,
    stream_id: u64 = 0,
    buf: SendBuffer = .{},
};

pub fn findStreamSendSlot(slots: []StreamSendSlot, stream_id: u64) ?*SendBuffer {
    for (slots) |*slot| {
        if (slot.active and slot.stream_id == stream_id) return &slot.buf;
    }
    return null;
}

pub fn getOrCreateStreamSendSlot(
    slots: []StreamSendSlot,
    stream_id: u64,
) ?*SendBuffer {
    if (findStreamSendSlot(slots, stream_id)) |buf| return buf;
    for (slots) |*slot| {
        if (!slot.active) {
            slot.* = .{ .active = true, .stream_id = stream_id, .buf = .{} };
            return &slot.buf;
        }
    }
    return null;
}

pub fn releaseStreamSendSlot(slots: []StreamSendSlot, allocator: std.mem.Allocator, stream_id: u64) void {
    for (slots) |*slot| {
        if (slot.active and slot.stream_id == stream_id) {
            slot.buf.deinit(allocator);
            slot.* = .{};
            return;
        }
    }
}

test "send_buffer: append coalesce and poll" {
    const testing = std.testing;
    var buf: SendBuffer = .{};
    defer buf.deinit(testing.allocator);

    try buf.append(testing.allocator, 0, "hello", false);
    try buf.append(testing.allocator, 5, " world", false);
    const p1 = buf.pollTransmit(8).?;
    try testing.expectEqual(@as(u64, 0), p1.offset);
    try testing.expectEqualSlices(u8, "hello wo", p1.data);
    buf.onSent(p1.offset, p1.data.len);

    const p2 = buf.pollTransmit(8).?;
    try testing.expectEqual(@as(u64, 8), p2.offset);
    try testing.expectEqualSlices(u8, "rld", p2.data);
}

test "send_buffer: partial loss retransmit" {
    const testing = std.testing;
    var buf: SendBuffer = .{};
    defer buf.deinit(testing.allocator);

    try buf.append(testing.allocator, 0, "abcdefghij", false);
    const p = buf.pollTransmit(10).?;
    buf.onSent(p.offset, p.data.len);
    try buf.onLoss(testing.allocator, 2, 4);
    const rtx = buf.pollTransmit(2).?;
    try testing.expectEqual(@as(u64, 2), rtx.offset);
    try testing.expectEqualSlices(u8, "cd", rtx.data);
    buf.onSent(rtx.offset, rtx.data.len);
    const rtx2 = buf.pollTransmit(10).?;
    try testing.expectEqual(@as(u64, 4), rtx2.offset);
    try testing.expectEqualSlices(u8, "ef", rtx2.data);
}

test "send_buffer: ack frees head" {
    const testing = std.testing;
    var buf: SendBuffer = .{};
    defer buf.deinit(testing.allocator);

    try buf.append(testing.allocator, 0, "abc", false);
    const p = buf.pollTransmit(3).?;
    buf.onSent(p.offset, p.data.len);
    buf.onAck(testing.allocator, 0, 3);
    try testing.expectEqual(@as(usize, 0), buf.segments.items.len);
    try testing.expectEqual(@as(usize, 0), buf.queued_bytes);
}

test "send_buffer: fin only" {
    const testing = std.testing;
    var buf: SendBuffer = .{};
    defer buf.deinit(testing.allocator);

    try buf.append(testing.allocator, 100, &.{}, true);
    const p = buf.pollTransmit(64).?;
    try testing.expect(p.fin);
    try testing.expectEqual(@as(u64, 100), p.offset);
}

test "send_buffer: overlapping onLoss calls coalesce (regression for infinite-recurse mergeLost)" {
    const testing = std.testing;
    var buf: SendBuffer = .{};
    defer buf.deinit(testing.allocator);

    try buf.append(testing.allocator, 0, "abcdefghij", false);
    _ = buf.pollTransmit(10);
    buf.onSent(0, 10);

    try buf.onLoss(testing.allocator, 0, 4);
    try testing.expectEqual(@as(usize, 1), buf.lost.items.len);

    try buf.onLoss(testing.allocator, 2, 4);
    try testing.expectEqual(@as(usize, 1), buf.lost.items.len);
    try testing.expectEqual(@as(u64, 0), buf.lost.items[0].offset);
    try testing.expectEqual(@as(usize, 6), buf.lost.items[0].len);

    try buf.onLoss(testing.allocator, 6, 2);
    try testing.expectEqual(@as(usize, 1), buf.lost.items.len);
    try testing.expectEqual(@as(usize, 8), buf.lost.items[0].len);
}

test "send_buffer: non-contiguous ack retains gap for retransmit (#221)" {
    const testing = std.testing;
    var buf: SendBuffer = .{};
    defer buf.deinit(testing.allocator);

    var data: [1632]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i % 256);

    try buf.append(testing.allocator, 0, &data, false);
    try testing.expectEqual(@as(usize, 1632), buf.queued_bytes);

    const p1 = buf.pollTransmit(1436).?;
    try testing.expectEqual(@as(u64, 0), p1.offset);
    try testing.expectEqual(@as(usize, 1436), p1.data.len);
    buf.onSent(p1.offset, p1.data.len);

    const p2 = buf.pollTransmit(196).?;
    try testing.expectEqual(@as(u64, 1436), p2.offset);
    try testing.expectEqual(@as(usize, 196), p2.data.len);
    buf.onSent(p2.offset, p2.data.len);

    // ACK only the tail packet — must not treat the leading gap as acked.
    buf.onAck(testing.allocator, 1436, 196);
    try testing.expectEqual(@as(usize, 1), buf.segments.items.len);
    try testing.expectEqual(@as(usize, 1436), buf.queued_bytes);
    try testing.expectEqual(@as(usize, 0), contiguousAckedEnd(buf.segments.items[0].acked_ranges.items));

    try buf.onLoss(testing.allocator, 0, 1436);
    const rtx = buf.pollTransmit(1436).?;
    try testing.expectEqual(@as(u64, 0), rtx.offset);
    try testing.expectEqual(@as(usize, 1436), rtx.data.len);
    try testing.expectEqualSlices(u8, data[0..1436], rtx.data);

    buf.onSent(rtx.offset, rtx.data.len);
    buf.onAck(testing.allocator, 0, 1436);
    try testing.expectEqual(@as(usize, 0), buf.segments.items.len);
    try testing.expectEqual(@as(usize, 0), buf.queued_bytes);
}
