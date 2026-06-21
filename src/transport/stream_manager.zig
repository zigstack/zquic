//! QUIC stream multiplexing (RFC 9000 §2, §3).
//!
//! Stream IDs encode the initiator and directionality:
//!   Bit 0: 0=client-initiated, 1=server-initiated
//!   Bit 1: 0=bidirectional, 1=unidirectional
//!
//! Each stream has a state machine:
//!   Idle → Open → Half-Closed (local) → Closed
//!             └─→ Half-Closed (remote) ┘
//!             └─→ Reset (sent/received)

const std = @import("std");
const types = @import("../types.zig");
const flow_control = @import("flow_control.zig");
const stream_frame = @import("../frames/stream.zig");
const frames = @import("../frames/transport.zig");

/// Small out-of-order buffer for classic streams (UDP reorder / loss recovery).
const StreamReorderSlot = struct {
    used: bool = false,
    offset: u64 = 0,
    len: usize = 0,
    data: [stream_reorder_chunk_max]u8 = undefined,
};

const stream_reorder_slots: usize = 8;
const stream_reorder_chunk_max: usize = 1450;

const StreamReorderBuf = struct {
    slots: [stream_reorder_slots]StreamReorderSlot = [_]StreamReorderSlot{.{}} ** stream_reorder_slots,

    fn insert(self: *StreamReorderBuf, offset: u64, data: []const u8) void {
        if (data.len > stream_reorder_chunk_max) return;
        for (&self.slots) |*slot| {
            if (slot.used and slot.offset == offset) return;
        }
        for (&self.slots) |*slot| {
            if (!slot.used) {
                slot.offset = offset;
                slot.len = data.len;
                slot.used = true;
                @memcpy(slot.data[0..data.len], data);
                return;
            }
        }
        var oldest: usize = 0;
        for (1..stream_reorder_slots) |i| {
            if (self.slots[i].used and self.slots[i].offset < self.slots[oldest].offset) {
                oldest = i;
            }
        }
        self.slots[oldest].offset = offset;
        self.slots[oldest].len = data.len;
        self.slots[oldest].used = true;
        @memcpy(self.slots[oldest].data[0..data.len], data);
    }

    fn take(self: *StreamReorderBuf, next_offset: u64, out: []u8) usize {
        for (&self.slots) |*slot| {
            if (slot.used and slot.offset == next_offset) {
                const n = @min(slot.len, out.len);
                @memcpy(out[0..n], slot.data[0..n]);
                slot.used = false;
                return n;
            }
        }
        return 0;
    }
};

pub const StreamId = types.StreamId;
pub const FlowControl = flow_control.StreamFlowControl;

/// Stream state (RFC 9000 §3)
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset_sent,
    reset_received,
};

pub const StreamStateError = error{InvalidStreamState};

/// A single QUIC stream.
pub const Stream = struct {
    id: StreamId,
    state: StreamState = .idle,
    fc: FlowControl,
    /// Receive buffer (in-order bytes ready for application consumption).
    recv_buf: [8192]u8 = undefined,
    recv_buf_start: usize = 0,
    recv_buf_end: usize = 0,
    /// Highest contiguous offset received.
    recv_offset: u64 = 0,
    /// Out-of-order STREAM segments waiting for `recv_offset` to advance.
    recv_reorder: StreamReorderBuf = .{},
    /// Offset at which we've consumed (app has read).
    read_offset: u64 = 0,
    /// Send offset (next byte to send).
    send_offset: u64 = 0,
    /// True if the local side sent FIN.
    fin_sent: bool = false,
    /// True if the remote side sent FIN or final size is known from RESET.
    fin_received: bool = false,
    /// Final size (RFC 9000 §19.4): agreed cumulative byte count for the stream.
    fin_size: u64 = 0,

    pub fn init(id: StreamId, send_max: u64, recv_max: u64) Stream {
        return .{
            .id = id,
            .fc = FlowControl.init(send_max, recv_max),
        };
    }

    pub fn transitionAllowed(from: StreamState, to: StreamState) bool {
        if (from == to) return true;
        return switch (from) {
            .idle => to == .open,
            .open => switch (to) {
                .half_closed_local, .half_closed_remote, .closed, .reset_sent, .reset_received => true,
                else => false,
            },
            .half_closed_local => switch (to) {
                .closed, .reset_received => true,
                else => false,
            },
            .half_closed_remote => switch (to) {
                .closed, .reset_received => true,
                else => false,
            },
            .closed, .reset_sent, .reset_received => false,
        };
    }

    fn setState(self: *Stream, next: StreamState) StreamStateError!void {
        if (!transitionAllowed(self.state, next)) return error.InvalidStreamState;
        self.state = next;
    }

    fn appendContiguous(self: *Stream, data: []const u8) bool {
        const avail = self.recv_buf.len - self.recv_buf_end;
        if (data.len > avail) return false;
        @memcpy(self.recv_buf[self.recv_buf_end .. self.recv_buf_end + data.len], data);
        self.recv_buf_end += data.len;
        self.recv_offset += @intCast(data.len);
        return true;
    }

    fn flushReorder(self: *Stream) void {
        var drain_buf: [stream_reorder_chunk_max]u8 = undefined;
        while (true) {
            const n = self.recv_reorder.take(self.recv_offset, &drain_buf);
            if (n == 0) break;
            if (!self.appendContiguous(drain_buf[0..n])) break;
        }
    }

    /// True when `[off, off+len)` partially overlaps a buffered out-of-order segment.
    fn overlapsPending(self: *const Stream, off: u64, len: usize) bool {
        if (len == 0) return false;
        const end = off + len;
        for (self.recv_reorder.slots) |slot| {
            if (!slot.used) continue;
            const slot_end = slot.offset + slot.len;
            if (off < slot_end and end > slot.offset) {
                if (off == slot.offset and len == slot.len) return false;
                return true;
            }
        }
        return false;
    }

    fn applyFin(self: *Stream, fin: bool, frame_offset: u64, frame_len: usize) bool {
        if (!fin) return true;
        const new_fin_size = frame_offset + frame_len;
        if (self.fin_received and new_fin_size != self.fin_size) return false;
        self.fin_received = true;
        self.fin_size = new_fin_size;
        const next: StreamState = if (self.state == .half_closed_local) .closed else .half_closed_remote;
        self.setState(next) catch return false;
        return true;
    }

    /// Write `data` into the receive buffer. Returns false on flow control
    /// violation, invalid state, overlapping out-of-order data, or buffer full.
    pub fn onRecvData(self: *Stream, offset: u64, data: []const u8, fin: bool) bool {
        if (self.state == .closed or self.state == .reset_received or self.state == .reset_sent)
            return false;

        if (!self.fc.onReceive(offset, data.len)) return false;

        var off = offset;
        var payload = data;
        const frame_end = offset + data.len;

        // Wholly duplicate retransmit.
        if (frame_end <= self.recv_offset) {
            return self.applyFin(fin, offset, data.len);
        }

        // Trim bytes already contiguously received (common on loss recovery).
        if (off < self.recv_offset) {
            const skip = @as(usize, @intCast(self.recv_offset - off));
            if (skip >= payload.len) return self.applyFin(fin, offset, data.len);
            payload = payload[skip..];
            off = self.recv_offset;
        }

        if (self.overlapsPending(off, payload.len)) return false;

        if (off == self.recv_offset) {
            if (!self.appendContiguous(payload)) return false;
            self.flushReorder();
        } else if (off > self.recv_offset) {
            if (payload.len > stream_reorder_chunk_max) return false;
            self.recv_reorder.insert(off, payload);
            self.flushReorder();
        }

        return self.applyFin(fin, offset, data.len);
    }

    /// Remote RESET_STREAM (RFC 9000 §19.4). `final_size` must match any prior FIN.
    pub fn onRecvReset(self: *Stream, final_size: u64) bool {
        if (self.state == .closed) {
            return final_size == self.fin_size;
        }
        if (self.state == .reset_received) {
            return final_size == self.fin_size;
        }
        if (self.fin_received and final_size != self.fin_size) return false;
        self.fin_received = true;
        self.fin_size = final_size;
        self.setState(.reset_received) catch return false;
        return true;
    }

    /// Read up to `out.len` bytes from the receive buffer into `out`.
    pub fn read(self: *Stream, out: []u8) usize {
        const available = self.recv_buf_end - self.recv_buf_start;
        const n = @min(available, out.len);
        @memcpy(out[0..n], self.recv_buf[self.recv_buf_start .. self.recv_buf_start + n]);
        self.recv_buf_start += n;
        self.read_offset += n;
        if (self.recv_buf_start == self.recv_buf_end) {
            self.recv_buf_start = 0;
            self.recv_buf_end = 0;
        }
        return n;
    }

    /// Mark local side as finished (FIN will be sent in next STREAM frame).
    pub fn closeLocal(self: *Stream) void {
        if (self.state == .closed or self.state == .reset_sent or self.state == .reset_received)
            return;
        self.fin_sent = true;
        const next: StreamState = if (self.state == .half_closed_remote) .closed else .half_closed_local;
        self.setState(next) catch return;
    }
};

/// Manages all streams for a connection.
pub const StreamManager = struct {
    const max_streams = 64;

    role: types.StreamId.Initiator,
    streams: [max_streams]?Stream = [_]?Stream{null} ** max_streams,
    stream_count: usize = 0,

    /// Limits for stream creation.
    max_bidi_streams: u64 = 100,
    max_uni_streams: u64 = 100,

    /// Next stream IDs to create.
    next_bidi_id: u62 = 0,
    next_uni_id: u62 = 0,

    pub fn init(role: types.StreamId.Initiator) StreamManager {
        return .{ .role = role };
    }

    /// Open a new bidirectional stream. Returns the stream or null if at limit.
    pub fn openBidi(self: *StreamManager) ?*Stream {
        const n = self.next_bidi_id;
        if (n >= self.max_bidi_streams) return null;
        const sid = switch (self.role) {
            .client => StreamId.nextClientBidirectional(n),
            .server => StreamId{ .id = n * 4 + 1 },
        };
        self.next_bidi_id += 1;
        return self.allocStream(sid);
    }

    /// Open a new unidirectional stream.
    pub fn openUni(self: *StreamManager) ?*Stream {
        const n = self.next_uni_id;
        if (n >= self.max_uni_streams) return null;
        const sid = switch (self.role) {
            .client => StreamId.nextClientUnidirectional(n),
            .server => StreamId{ .id = n * 4 + 3 },
        };
        self.next_uni_id += 1;
        return self.allocStream(sid);
    }

    fn allocStream(self: *StreamManager, sid: StreamId) ?*Stream {
        if (self.stream_count >= max_streams) return null;
        for (&self.streams) |*slot| {
            if (slot.* == null) {
                slot.* = Stream.init(sid, 256_000, 256_000);
                slot.*.?.state = .open;
                self.stream_count += 1;
                return &(slot.*.?);
            }
        }
        return null;
    }

    /// Find a stream by ID.
    pub fn findStream(self: *StreamManager, sid: StreamId) ?*Stream {
        for (&self.streams) |*slot| {
            if (slot.*) |*s| {
                if (s.id.id == sid.id) return s;
            }
        }
        return null;
    }

    /// Process an incoming STREAM frame.
    pub fn onStreamFrame(self: *StreamManager, f: stream_frame.StreamFrame) bool {
        const sid = StreamId.init(@intCast(f.stream_id));
        if (self.findStream(sid)) |s| {
            return s.onRecvData(f.offset, f.data, f.fin);
        }
        // Auto-create stream for peer-initiated streams
        if (self.allocStream(sid)) |s| {
            return s.onRecvData(f.offset, f.data, f.fin);
        }
        return false;
    }

    /// Process an incoming RESET_STREAM frame (RFC 9000 §19.4).
    pub fn onResetStreamFrame(self: *StreamManager, f: frames.ResetStream) bool {
        const sid = StreamId.init(@intCast(f.stream_id));
        if (self.findStream(sid)) |s| {
            return s.onRecvReset(f.final_size);
        }
        if (self.allocStream(sid)) |s| {
            return s.onRecvReset(f.final_size);
        }
        return false;
    }
};

test "stream: basic read/write" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 100_000);
    s.state = .open;

    try testing.expect(s.onRecvData(0, "hello", false));
    try testing.expect(s.onRecvData(5, " world", true));

    var out: [32]u8 = undefined;
    const n = s.read(&out);
    try testing.expectEqualSlices(u8, "hello world", out[0..n]);
    try testing.expect(s.fin_received);
}

test "stream: FIN final size mismatch" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 100_000);
    s.state = .open;
    try testing.expect(s.onRecvData(0, "ab", true));
    try testing.expect(!s.onRecvData(0, "abc", true));
}

test "stream: RESET matches FIN final size" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 100_000);
    s.state = .open;
    try testing.expect(s.onRecvData(0, "x", true));
    try testing.expect(s.onRecvReset(1));
    try testing.expect(s.state == .reset_received);
}

test "stream: RESET conflicts with FIN size" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 100_000);
    s.state = .open;
    try testing.expect(s.onRecvData(0, "x", true));
    try testing.expect(!s.onRecvReset(99));
}

test "stream: closeLocal transitions" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 100_000);
    s.state = .open;
    s.closeLocal();
    try testing.expect(s.state == .half_closed_local);
    try testing.expect(s.onRecvData(0, "a", true));
    try testing.expect(s.state == .closed);
}

test "stream_manager: open and find streams" {
    const testing = std.testing;
    var mgr = StreamManager.init(.client);

    const s1 = mgr.openBidi();
    try testing.expect(s1 != null);
    try testing.expectEqual(@as(u62, 0), s1.?.id.id);

    const s2 = mgr.openBidi();
    try testing.expect(s2 != null);
    try testing.expectEqual(@as(u62, 4), s2.?.id.id);

    const found = mgr.findStream(StreamId.init(0));
    try testing.expect(found != null);
}

test "stream_manager: process stream frame" {
    const testing = std.testing;
    var mgr = StreamManager.init(.server);

    const f = stream_frame.StreamFrame{
        .stream_id = 0, // client-initiated bidi
        .offset = 0,
        .data = "ping",
        .fin = false,
        .has_length = true,
    };
    try testing.expect(mgr.onStreamFrame(f));

    const s = mgr.findStream(StreamId.init(0));
    try testing.expect(s != null);
    var buf: [8]u8 = undefined;
    const n = s.?.read(&buf);
    try testing.expectEqualSlices(u8, "ping", buf[0..n]);
}

test "stream_manager: RESET_STREAM frame" {
    const testing = std.testing;
    var mgr = StreamManager.init(.server);
    const rs = frames.ResetStream{
        .stream_id = 4,
        .application_protocol_error_code = 0x100,
        .final_size = 0,
    };
    try testing.expect(mgr.onResetStreamFrame(rs));
    const s = mgr.findStream(StreamId.init(4));
    try testing.expect(s != null);
    try testing.expect(s.?.state == .reset_received);
}

test "flow_control: stream flow control violation" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 10); // recv_max = 10

    try testing.expect(s.onRecvData(0, "hello", false)); // 5 bytes OK
    try testing.expect(!s.onRecvData(5, " world!", false)); // 7 more = 12 total > 10
}

test "stream: out-of-order gap fill" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 100_000);
    s.state = .open;

    try testing.expect(s.onRecvData(0, "abc", false));
    try testing.expect(s.onRecvData(6, "ghi", false));
    try testing.expectEqual(@as(u64, 3), s.recv_offset);

    try testing.expect(s.onRecvData(3, "def", false));
    try testing.expectEqual(@as(u64, 9), s.recv_offset);

    var out: [16]u8 = undefined;
    const n = s.read(&out);
    try testing.expectEqualSlices(u8, "abcdefghi", out[0..n]);
}

test "stream: duplicate retransmit is ignored" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 100_000);
    s.state = .open;

    try testing.expect(s.onRecvData(0, "hello", false));
    try testing.expect(s.onRecvData(0, "hello", false));
    try testing.expectEqual(@as(u64, 5), s.recv_offset);
}

test "stream: overlapping out-of-order segment rejected" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 100_000);
    s.state = .open;

    try testing.expect(s.onRecvData(5, "tail", false));
    try testing.expect(!s.onRecvData(6, "x", false));
}
