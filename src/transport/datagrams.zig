//! RFC 9221 application datagram receive queue.

const std = @import("std");

pub const max_recv_queue: usize = 64;
pub const max_payload: usize = 1200;

const Entry = struct {
    len: usize = 0,
    data: [max_payload]u8 = undefined,
};

pub const RecvQueue = struct {
    ring: [max_recv_queue]Entry = [_]Entry{.{}} ** max_recv_queue,
    head: usize = 0,
    count: usize = 0,
    dropped: u64 = 0,

    pub fn push(self: *RecvQueue, payload: []const u8) void {
        const n = @min(payload.len, max_payload);
        if (self.count >= max_recv_queue) {
            self.head = (self.head + 1) % max_recv_queue;
            self.count -= 1;
            self.dropped += 1;
        }
        const idx = (self.head + self.count) % max_recv_queue;
        @memcpy(self.ring[idx].data[0..n], payload[0..n]);
        self.ring[idx].len = n;
        self.count += 1;
    }

    pub fn pop(self: *RecvQueue) ?[]const u8 {
        if (self.count == 0) return null;
        const e = &self.ring[self.head];
        const slice = e.data[0..e.len];
        self.head = (self.head + 1) % max_recv_queue;
        self.count -= 1;
        return slice;
    }

    pub fn hasPending(self: *const RecvQueue) bool {
        return self.count > 0;
    }
};

test "datagrams: push drops oldest when full" {
    var q: RecvQueue = .{};
    var i: usize = 0;
    while (i < max_recv_queue + 2) : (i += 1) {
        var buf: [4]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "{d}", .{i}) catch unreachable;
        q.push(&buf);
    }
    try std.testing.expect(q.dropped >= 1);
    try std.testing.expectEqual(@as(usize, max_recv_queue), q.count);
}
