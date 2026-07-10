//! All QUIC frame types (RFC 9000 §12.4, §19).
//!
//! Frame type → wire encoding (first varint):
//!   PADDING           0x00
//!   PING              0x01
//!   ACK               0x02 / 0x03
//!   RESET_STREAM      0x04
//!   STOP_SENDING      0x05
//!   CRYPTO            0x06
//!   NEW_TOKEN         0x07
//!   STREAM            0x08–0x0f
//!   MAX_DATA          0x10
//!   MAX_STREAM_DATA   0x11
//!   MAX_STREAMS (bi)  0x12
//!   MAX_STREAMS (uni) 0x13
//!   DATA_BLOCKED      0x14
//!   STREAM_DATA_BLOCKED 0x15
//!   STREAMS_BLOCKED (bi)  0x16
//!   STREAMS_BLOCKED (uni) 0x17
//!   NEW_CONNECTION_ID   0x18
//!   RETIRE_CONNECTION_ID 0x19
//!   PATH_CHALLENGE    0x1a
//!   PATH_RESPONSE     0x1b
//!   CONNECTION_CLOSE  0x1c / 0x1d
//!   HANDSHAKE_DONE    0x1e
//!   IMMEDIATE_ACK     0x1f          (draft-ietf-quic-ack-frequency)
//!   DATAGRAM          0x30 / 0x31  (RFC 9221)
//!   ACK_FREQUENCY     0xaf          (draft-ietf-quic-ack-frequency)

const std = @import("std");
const varint = @import("../varint.zig");
const types = @import("../types.zig");

pub const ack = @import("ack.zig");
pub const crypto_frame = @import("crypto_frame.zig");
pub const datagram_mod = @import("datagram.zig");
pub const ack_frequency_mod = @import("ack_frequency.zig");
pub const stream = @import("stream.zig");
pub const transport = @import("transport.zig");

pub const FrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    // STREAM 0x08–0x0f (flags in low 3 bits)
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close_quic = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,
    immediate_ack = 0x1f,
    _,
};

/// A parsed QUIC frame, representing one of the many frame types.
pub const Frame = union(enum) {
    padding: transport.Padding,
    ping: transport.Ping,
    ack: ack.AckFrame,
    reset_stream: transport.ResetStream,
    stop_sending: transport.StopSending,
    crypto: crypto_frame.CryptoFrame,
    new_token: transport.NewToken,
    stream: stream.StreamFrame,
    max_data: transport.MaxData,
    max_stream_data: transport.MaxStreamData,
    max_streams_bidi: transport.MaxStreams,
    max_streams_uni: transport.MaxStreams,
    data_blocked: transport.DataBlocked,
    stream_data_blocked: transport.StreamDataBlocked,
    streams_blocked_bidi: transport.StreamsBlocked,
    streams_blocked_uni: transport.StreamsBlocked,
    new_connection_id: transport.NewConnectionId,
    retire_connection_id: transport.RetireConnectionId,
    path_challenge: transport.PathChallenge,
    path_response: transport.PathResponse,
    connection_close: transport.ConnectionClose,
    handshake_done: transport.HandshakeDone,
    datagram: datagram_mod.DatagramFrame,
    immediate_ack: ack_frequency_mod.ImmediateAck,
    ack_frequency: ack_frequency_mod.AckFrequencyFrame,

    /// Returns true if this frame type is allowed in Initial packets.
    pub fn allowedInInitial(self: Frame) bool {
        return switch (self) {
            .padding, .ping, .crypto, .connection_close, .ack => true,
            else => false,
        };
    }

    /// Returns true if this frame type is allowed in Handshake packets.
    pub fn allowedInHandshake(self: Frame) bool {
        return switch (self) {
            .padding, .ping, .crypto, .connection_close, .ack => true,
            else => false,
        };
    }
};

pub const ParseError = varint.DecodeError || error{
    UnknownFrameType,
    InvalidFrame,
    BufferTooShort,
    TooLong,
    FrameEncodingError,
};

/// Parse one frame from `buf`. Returns the frame and bytes consumed.
pub fn parseOne(buf: []const u8) ParseError!struct { frame: Frame, consumed: usize } {
    if (buf.len == 0) return error.BufferTooShort;

    const type_r = try varint.decode(buf);
    const pos: usize = type_r.len;
    const ft = type_r.value;

    // STREAM frames: type 0x08..0x0f
    if (ft >= 0x08 and ft <= 0x0f) {
        const r = try stream.StreamFrame.parse(buf[pos..], ft);
        return .{ .frame = .{ .stream = r.frame }, .consumed = pos + r.consumed };
    }

    switch (ft) {
        0x00 => {
            // PADDING: one or more 0x00 bytes; consume all consecutive zeros
            var count: usize = 0;
            while (pos + count < buf.len and buf[pos + count] == 0x00) : (count += 1) {}
            return .{ .frame = .{ .padding = .{ .length = count + 1 } }, .consumed = pos + count };
        },
        0x01 => return .{ .frame = .{ .ping = .{} }, .consumed = pos },
        0x02, 0x03 => {
            const r = try ack.AckFrame.parse(buf[pos..], ft == 0x03);
            return .{ .frame = .{ .ack = r.frame }, .consumed = pos + r.consumed };
        },
        0x04 => {
            const r = try transport.ResetStream.parse(buf[pos..]);
            return .{ .frame = .{ .reset_stream = r.frame }, .consumed = pos + r.consumed };
        },
        0x05 => {
            const r = try transport.StopSending.parse(buf[pos..]);
            return .{ .frame = .{ .stop_sending = r.frame }, .consumed = pos + r.consumed };
        },
        0x06 => {
            const r = try crypto_frame.CryptoFrame.parse(buf[pos..]);
            return .{ .frame = .{ .crypto = r.frame }, .consumed = pos + r.consumed };
        },
        0x07 => {
            const r = try transport.NewToken.parse(buf[pos..]);
            return .{ .frame = .{ .new_token = r.frame }, .consumed = pos + r.consumed };
        },
        0x10 => {
            const r = try varint.decode(buf[pos..]);
            return .{ .frame = .{ .max_data = .{ .maximum_data = r.value } }, .consumed = pos + r.len };
        },
        0x11 => {
            const r = try transport.MaxStreamData.parse(buf[pos..]);
            return .{ .frame = .{ .max_stream_data = r.frame }, .consumed = pos + r.consumed };
        },
        0x12 => {
            const r = try varint.decode(buf[pos..]);
            return .{ .frame = .{ .max_streams_bidi = .{ .maximum_streams = r.value } }, .consumed = pos + r.len };
        },
        0x13 => {
            const r = try varint.decode(buf[pos..]);
            return .{ .frame = .{ .max_streams_uni = .{ .maximum_streams = r.value } }, .consumed = pos + r.len };
        },
        0x14 => {
            const r = try varint.decode(buf[pos..]);
            return .{ .frame = .{ .data_blocked = .{ .maximum_data = r.value } }, .consumed = pos + r.len };
        },
        0x15 => {
            const r = try transport.StreamDataBlocked.parse(buf[pos..]);
            return .{ .frame = .{ .stream_data_blocked = r.frame }, .consumed = pos + r.consumed };
        },
        0x16 => {
            const r = try varint.decode(buf[pos..]);
            return .{ .frame = .{ .streams_blocked_bidi = .{ .maximum_streams = r.value } }, .consumed = pos + r.len };
        },
        0x17 => {
            const r = try varint.decode(buf[pos..]);
            return .{ .frame = .{ .streams_blocked_uni = .{ .maximum_streams = r.value } }, .consumed = pos + r.len };
        },
        0x18 => {
            const r = try transport.NewConnectionId.parse(buf[pos..]);
            return .{ .frame = .{ .new_connection_id = r.frame }, .consumed = pos + r.consumed };
        },
        0x19 => {
            const r = try varint.decode(buf[pos..]);
            return .{ .frame = .{ .retire_connection_id = .{ .sequence_number = r.value } }, .consumed = pos + r.len };
        },
        0x1a => {
            if (buf.len < pos + 8) return error.BufferTooShort;
            var data: [8]u8 = undefined;
            @memcpy(&data, buf[pos .. pos + 8]);
            return .{ .frame = .{ .path_challenge = .{ .data = data } }, .consumed = pos + 8 };
        },
        0x1b => {
            if (buf.len < pos + 8) return error.BufferTooShort;
            var data: [8]u8 = undefined;
            @memcpy(&data, buf[pos .. pos + 8]);
            return .{ .frame = .{ .path_response = .{ .data = data } }, .consumed = pos + 8 };
        },
        0x1c, 0x1d => {
            const r = try transport.ConnectionClose.parse(buf[pos..], ft == 0x1d);
            return .{ .frame = .{ .connection_close = r.frame }, .consumed = pos + r.consumed };
        },
        0x1e => return .{ .frame = .{ .handshake_done = .{} }, .consumed = pos },
        0x1f => return .{ .frame = .{ .immediate_ack = .{} }, .consumed = pos },
        0x30, 0x31 => {
            const r = try datagram_mod.DatagramFrame.parse(buf[pos..], ft);
            return .{ .frame = .{ .datagram = r.frame }, .consumed = pos + r.consumed };
        },
        ack_frequency_mod.ack_frequency_frame_type => {
            const r = try ack_frequency_mod.AckFrequencyFrame.parse(buf[pos..]);
            return .{ .frame = .{ .ack_frequency = r.frame }, .consumed = pos + r.consumed };
        },
        else => return error.UnknownFrameType,
    }
}

test "frame: parse PING" {
    const testing = std.testing;
    var buf = [_]u8{0x01};
    const r = try parseOne(&buf);
    try testing.expect(r.frame == .ping);
    try testing.expectEqual(@as(usize, 1), r.consumed);
}

test "frame: parse PADDING" {
    const testing = std.testing;
    var buf = [_]u8{ 0x00, 0x00, 0x00 };
    const r = try parseOne(&buf);
    try testing.expect(r.frame == .padding);
    try testing.expectEqual(@as(usize, 3), r.consumed);
}

test "frame: parse PATH_CHALLENGE" {
    const testing = std.testing;
    var buf = [_]u8{ 0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const r = try parseOne(&buf);
    try testing.expect(r.frame == .path_challenge);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, &r.frame.path_challenge.data);
}
