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

const Segment = struct {
    offset: u64,
    data: []u8,
    /// Bytes from the start of this segment that have been put on the wire and
    /// are not yet ACKed (includes in-flight and lost ranges).
    sent: usize = 0,
    /// Bytes from the start of this segment that the peer has ACKed.
    acked: usize = 0,
};

pub const PollResult = struct {
    offset: u64,
    data: []const u8,
    fin: bool,
    /// True when this slice comes from a lost range (retransmit).
    retransmit: bool = false,
};

pub const SendBuffer = struct {
    segments: std.ArrayList(Segment) = .empty,
    lost: std.ArrayList(Range) = .empty,
    /// Stream end offset when FIN was queued (exclusive).
    fin_at: ?u64 = null,
    fin_sent: bool = false,
    queued_bytes: usize = 0,

    pub fn deinit(self: *SendBuffer, allocator: std.mem.Allocator) void {
        for (self.segments.items) |seg| allocator.free(seg.data);
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
            if (seg.acked < seg.data.len) break;
            allocator.free(seg.data);
            _ = self.segments.orderedRemove(0);
        }
        var i: usize = 0;
        while (i < self.lost.items.len) {
            const r = self.lost.items[i];
            if (self.segments.items.len == 0) break;
            const head = self.segments.items[0];
            if (r.offset + r.len <= head.offset + head.acked) {
                _ = self.lost.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn mergeLost(self: *SendBuffer, allocator: std.mem.Allocator, offset: u64, len: usize) !void {
        if (len == 0) return;
        // Walk once, absorbing every overlapping / adjacent range into a single
        // accumulator. The previous version recursed with the ORIGINAL
        // (offset, len) after each merge — since the merged range still overlaps
        // with those args, the recursion never terminated (release builds TCO'd
        // it into a CPU spin, which is exactly the symptom the post-rebase
        // interop hit: transfer stalled with `pending_stream_sends` drained but
        // CC stuck in recovery and bif > cwnd).
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
            // Don't increment i — the shifted-down entry takes this slot.
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
            const rel_end: usize = @intCast(@min(end, seg_end) - seg.offset);
            if (rel_end > seg.acked) {
                const delta = rel_end - seg.acked;
                seg.acked = rel_end;
                self.queued_bytes -|= delta;
            }
            if (rel_end > seg.sent) seg.sent = rel_end;
        }
        self.pruneAcked(allocator);
    }

    /// Mark `[offset, offset+len)` as lost — eligible for `pollTransmit`.
    pub fn onLoss(self: *SendBuffer, allocator: std.mem.Allocator, offset: u64, len: usize) !void {
        if (len == 0) return;
        try self.mergeLost(allocator, offset, len);
        for (self.segments.items) |*seg| {
            const seg_end = seg.offset + seg.data.len;
            if (offset >= seg_end or offset + len <= seg.offset) continue;
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

pub const stream_send_slot_max: usize = 64;

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

    // First lost range; alone, append-only path is exercised.
    try buf.onLoss(testing.allocator, 0, 4);
    try testing.expectEqual(@as(usize, 1), buf.lost.items.len);

    // Second lost range overlapping the first — previously triggered
    // mergeLost's terminal-recurse-with-original-args spin.
    try buf.onLoss(testing.allocator, 2, 4);
    try testing.expectEqual(@as(usize, 1), buf.lost.items.len);
    try testing.expectEqual(@as(u64, 0), buf.lost.items[0].offset);
    try testing.expectEqual(@as(usize, 6), buf.lost.items[0].len);

    // Third lost range adjacent to the merged range — also merges.
    try buf.onLoss(testing.allocator, 6, 2);
    try testing.expectEqual(@as(usize, 1), buf.lost.items.len);
    try testing.expectEqual(@as(usize, 8), buf.lost.items[0].len);
}
