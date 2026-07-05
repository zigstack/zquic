//! Miscellaneous QUIC transport frames (RFC 9000 §19).

const std = @import("std");
const varint = @import("../varint.zig");
const types = @import("../types.zig");

pub const Padding = struct {
    length: usize,
};

pub const Ping = struct {};
pub const HandshakeDone = struct {};

pub const ResetStream = struct {
    stream_id: u64,
    application_protocol_error_code: u64,
    final_size: u64,

    pub fn parse(buf: []const u8) varint.DecodeError!struct { frame: ResetStream, consumed: usize } {
        var r = varint.Reader.init(buf);
        const sid = try r.readVarint();
        const code = try r.readVarint();
        const size = try r.readVarint();
        return .{ .frame = .{ .stream_id = sid, .application_protocol_error_code = code, .final_size = size }, .consumed = r.pos };
    }

    pub fn serialize(self: ResetStream, buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
        var w = varint.Writer.init(buf);
        try w.writeVarint(0x04);
        try w.writeVarint(self.stream_id);
        try w.writeVarint(self.application_protocol_error_code);
        try w.writeVarint(self.final_size);
        return w.pos;
    }
};

pub const StopSending = struct {
    stream_id: u64,
    application_protocol_error_code: u64,

    pub fn parse(buf: []const u8) varint.DecodeError!struct { frame: StopSending, consumed: usize } {
        var r = varint.Reader.init(buf);
        const sid = try r.readVarint();
        const code = try r.readVarint();
        return .{ .frame = .{ .stream_id = sid, .application_protocol_error_code = code }, .consumed = r.pos };
    }

    pub fn serialize(self: StopSending, buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
        var w = varint.Writer.init(buf);
        try w.writeVarint(0x05);
        try w.writeVarint(self.stream_id);
        try w.writeVarint(self.application_protocol_error_code);
        return w.pos;
    }
};

pub const NewToken = struct {
    token: []const u8,

    pub fn parse(buf: []const u8) varint.DecodeError!struct { frame: NewToken, consumed: usize } {
        var r = varint.Reader.init(buf);
        const len = try r.readVarint();
        const len_usize = try varint.lenToUsize(len);
        const token = try r.readBytes(len_usize);
        return .{ .frame = .{ .token = token }, .consumed = r.pos };
    }
};

pub const MaxData = struct {
    maximum_data: u64,
};

pub const MaxStreamData = struct {
    stream_id: u64,
    maximum_stream_data: u64,

    pub fn parse(buf: []const u8) varint.DecodeError!struct { frame: MaxStreamData, consumed: usize } {
        var r = varint.Reader.init(buf);
        const sid = try r.readVarint();
        const max = try r.readVarint();
        return .{ .frame = .{ .stream_id = sid, .maximum_stream_data = max }, .consumed = r.pos };
    }
};

pub const MaxStreams = struct {
    maximum_streams: u64,
};

pub const DataBlocked = struct {
    maximum_data: u64,
};

pub const StreamDataBlocked = struct {
    stream_id: u64,
    maximum_stream_data: u64,

    pub fn parse(buf: []const u8) varint.DecodeError!struct { frame: StreamDataBlocked, consumed: usize } {
        var r = varint.Reader.init(buf);
        const sid = try r.readVarint();
        const max = try r.readVarint();
        return .{ .frame = .{ .stream_id = sid, .maximum_stream_data = max }, .consumed = r.pos };
    }
};

pub const StreamsBlocked = struct {
    maximum_streams: u64,
};

pub const NewConnectionId = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: types.ConnectionId,
    stateless_reset_token: [16]u8,

    pub fn parse(buf: []const u8) (varint.DecodeError || error{TooLong})!struct { frame: NewConnectionId, consumed: usize } {
        var r = varint.Reader.init(buf);
        const seq = try r.readVarint();
        const retire = try r.readVarint();
        if (r.remaining() < 1) return error.BufferTooShort;
        const cid_len = r.buf[r.pos];
        r.pos += 1;
        if (cid_len > types.max_cid_len) return error.TooLong;
        const cid_bytes = try r.readBytes(cid_len);
        const cid = try types.ConnectionId.fromSlice(cid_bytes);
        if (r.remaining() < 16) return error.BufferTooShort;
        const token_bytes = try r.readBytes(16);
        var token: [16]u8 = undefined;
        @memcpy(&token, token_bytes);
        return .{
            .frame = .{
                .sequence_number = seq,
                .retire_prior_to = retire,
                .connection_id = cid,
                .stateless_reset_token = token,
            },
            .consumed = r.pos,
        };
    }
};

pub const RetireConnectionId = struct {
    sequence_number: u64,
};

pub const PathChallenge = struct {
    data: [8]u8,

    pub fn parse(buf: []const u8) error{BufferTooShort}!struct { frame: PathChallenge, consumed: usize } {
        if (buf.len < 8) return error.BufferTooShort;
        var d: [8]u8 = undefined;
        @memcpy(&d, buf[0..8]);
        return .{ .frame = .{ .data = d }, .consumed = 8 };
    }

    pub fn serialize(self: PathChallenge, buf: []u8) error{BufferTooShort}!usize {
        if (buf.len < 9) return error.BufferTooShort;
        buf[0] = 0x1a;
        @memcpy(buf[1..9], &self.data);
        return 9;
    }
};

pub const PathResponse = struct {
    data: [8]u8,

    pub fn parse(buf: []const u8) error{BufferTooShort}!struct { frame: PathResponse, consumed: usize } {
        if (buf.len < 8) return error.BufferTooShort;
        var d: [8]u8 = undefined;
        @memcpy(&d, buf[0..8]);
        return .{ .frame = .{ .data = d }, .consumed = 8 };
    }

    pub fn serialize(self: PathResponse, buf: []u8) error{BufferTooShort}!usize {
        if (buf.len < 9) return error.BufferTooShort;
        buf[0] = 0x1b;
        @memcpy(buf[1..9], &self.data);
        return 9;
    }
};

pub const ConnectionClose = struct {
    is_application: bool,
    error_code: u64,
    frame_type: u64,
    reason_phrase: []const u8,

    pub fn parse(buf: []const u8, is_app: bool) varint.DecodeError!struct { frame: ConnectionClose, consumed: usize } {
        var r = varint.Reader.init(buf);
        const code = try r.readVarint();
        const ft: u64 = if (!is_app) try r.readVarint() else 0;
        const reason_len = try r.readVarint();
        const reason_usize = try varint.lenToUsize(reason_len);
        const reason = try r.readBytes(reason_usize);
        return .{
            .frame = .{
                .is_application = is_app,
                .error_code = code,
                .frame_type = ft,
                .reason_phrase = reason,
            },
            .consumed = r.pos,
        };
    }

    pub fn serialize(self: ConnectionClose, buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
        var w = varint.Writer.init(buf);
        try w.writeVarint(if (self.is_application) 0x1d else 0x1c);
        try w.writeVarint(self.error_code);
        if (!self.is_application) try w.writeVarint(self.frame_type);
        try w.writeVarint(self.reason_phrase.len);
        try w.writeBytes(self.reason_phrase);
        return w.pos;
    }
};

test "transport: RESET_STREAM round-trip" {
    const testing = std.testing;
    const frame = ResetStream{ .stream_id = 5, .application_protocol_error_code = 0, .final_size = 1000 };
    var buf: [32]u8 = undefined;
    const written = try frame.serialize(&buf);
    const r = try ResetStream.parse(buf[1..written]);
    try testing.expectEqual(@as(u64, 5), r.frame.stream_id);
    try testing.expectEqual(@as(u64, 1000), r.frame.final_size);
}

test "transport: CONNECTION_CLOSE round-trip" {
    const testing = std.testing;
    const frame = ConnectionClose{
        .is_application = false,
        .error_code = 0x0a, // PROTOCOL_VIOLATION
        .frame_type = 0x06,
        .reason_phrase = "bad frame",
    };
    var buf: [64]u8 = undefined;
    const written = try frame.serialize(&buf);
    const r = try ConnectionClose.parse(buf[1..written], false);
    try testing.expectEqual(@as(u64, 0x0a), r.frame.error_code);
    try testing.expectEqualSlices(u8, "bad frame", r.frame.reason_phrase);
}

test "transport: MAX_DATA parse" {
    const testing = std.testing;
    const frame = @import("frame.zig");
    var buf = [_]u8{ 0x10, 0x52, 0x34 }; // type=0x10, value=0x1234
    const r = try frame.parseOne(&buf);
    try testing.expectEqual(@as(u64, 0x1234), r.frame.max_data.maximum_data);
}

test "transport: CONNECTION_CLOSE application close round-trip" {
    const testing = std.testing;
    // Application-level close (type 0x1d) has no frame_type field.
    const frame = ConnectionClose{
        .is_application = true,
        .error_code = 0x0100, // H3_NO_ERROR
        .frame_type = 0,
        .reason_phrase = "shutdown",
    };
    var buf: [64]u8 = undefined;
    const written = try frame.serialize(&buf);
    // buf[0] should be type byte 0x1d
    try testing.expectEqual(@as(u8, 0x1d), buf[0]);
    const r = try ConnectionClose.parse(buf[1..written], true);
    try testing.expectEqual(@as(u64, 0x0100), r.frame.error_code);
    try testing.expectEqualSlices(u8, "shutdown", r.frame.reason_phrase);
    try testing.expect(r.frame.is_application);
}

test "transport: DATA_BLOCKED and STREAM_DATA_BLOCKED frame types" {
    const testing = std.testing;
    // DATA_BLOCKED (type 0x14) carries a varint limit.
    const frame = @import("frame.zig");
    var db_buf = [_]u8{ 0x14, 0x40, 0x64 }; // type=0x14, limit=100 (2-byte varint)
    const db_r = try frame.parseOne(&db_buf);
    try testing.expectEqual(@as(u64, 100), db_r.frame.data_blocked.maximum_data);

    // STREAM_DATA_BLOCKED (type 0x15) carries stream_id then limit.
    var sdb_buf = [_]u8{ 0x15, 0x04, 0x40, 0x64 }; // type, stream_id=4, limit=100
    const sdb_r = try frame.parseOne(&sdb_buf);
    try testing.expectEqual(@as(u64, 4), sdb_r.frame.stream_data_blocked.stream_id);
    try testing.expectEqual(@as(u64, 100), sdb_r.frame.stream_data_blocked.maximum_stream_data);
}
