//! RFC 9221 DATAGRAM frames (types 0x30 / 0x31).

const std = @import("std");
const varint = @import("../varint.zig");

pub const DATAGRAM_WITH_LEN: u64 = 0x30;
pub const DATAGRAM_NO_LEN: u64 = 0x31;

pub const DatagramFrame = struct {
    data: []const u8,

    /// Parse a DATAGRAM frame.  `frame_type` must be 0x30 or 0x31.
    /// For 0x31 the datagram payload is the remainder of `buf`.
    pub fn parse(buf: []const u8, frame_type: u64) varint.DecodeError!struct { frame: DatagramFrame, consumed: usize } {
        if (frame_type == DATAGRAM_WITH_LEN) {
            const len_r = try varint.decode(buf);
            const len = try varint.lenToUsize(len_r.value);
            if (buf.len < len_r.len + len) return error.BufferTooShort;
            return .{
                .frame = .{ .data = buf[len_r.len .. len_r.len + len] },
                .consumed = len_r.len + len,
            };
        }
        return .{ .frame = .{ .data = buf }, .consumed = buf.len };
    }

    /// Serialize with explicit length (type 0x30).
    pub fn serializeWithLength(self: DatagramFrame, buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
        var w = varint.Writer.init(buf);
        try w.writeVarint(DATAGRAM_WITH_LEN);
        try w.writeVarint(self.data.len);
        if (w.pos + self.data.len > buf.len) return error.BufferTooShort;
        @memcpy(buf[w.pos .. w.pos + self.data.len], self.data);
        return w.pos + self.data.len;
    }

    /// Serialize without length (type 0x31).  Must be the last frame in the packet.
    pub fn serializeNoLength(self: DatagramFrame, buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
        var w = varint.Writer.init(buf);
        try w.writeVarint(DATAGRAM_NO_LEN);
        if (w.pos + self.data.len > buf.len) return error.BufferTooShort;
        @memcpy(buf[w.pos .. w.pos + self.data.len], self.data);
        return w.pos + self.data.len;
    }
};

test "datagram: with-length round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    const payload = "hello-datagram";
    const dg = DatagramFrame{ .data = payload };
    const written = try dg.serializeWithLength(&buf);
    const r = try DatagramFrame.parse(buf[1..], DATAGRAM_WITH_LEN);
    _ = written;
    try testing.expectEqualSlices(u8, payload, r.frame.data);
}

test "datagram: no-length consumes remainder" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    const dg = DatagramFrame{ .data = "xyz" };
    const written = try dg.serializeNoLength(&buf);
    try testing.expect(written > 1);
    const r = try DatagramFrame.parse(buf[1..written], DATAGRAM_NO_LEN);
    try testing.expectEqualSlices(u8, "xyz", r.frame.data);
}
