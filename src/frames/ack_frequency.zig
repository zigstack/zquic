//! QUIC ACK Frequency extension frames (draft-ietf-quic-ack-frequency).
//!
//! Two frames let a sender tune how often the peer acknowledges:
//!   - ACK_FREQUENCY (0xaf): request an ack-eliciting threshold, a max ack
//!     delay, and a reordering threshold.
//!   - IMMEDIATE_ACK (0x1f): request an ACK right now (e.g. in PTO probes).
//!
//! Both are extension frames: an endpoint MUST NOT send them unless the peer
//! advertised the `min_ack_delay` transport parameter (0xff04de1b).  Frame
//! type 0xaf is > 0x3f, so it occupies a 2-byte varint on the wire (0x40 0xaf);
//! 0x1f fits in one byte.

const std = @import("std");
const varint = @import("../varint.zig");

/// Frame type values (draft-ietf-quic-ack-frequency §4/§5 provisional codepoints).
pub const ack_frequency_frame_type: u64 = 0xaf;
pub const immediate_ack_frame_type: u64 = 0x1f;

/// `min_ack_delay` transport parameter id (draft §3).  Value is in
/// MICROSECONDS (unlike max_ack_delay, which is milliseconds).
pub const min_ack_delay_tp_id: u64 = 0xff04de1b;

pub const AckFrequencyFrame = struct {
    /// Monotonically increasing per sender; receiver processes a frame only
    /// when its sequence number is strictly greater than any previously
    /// processed one (out-of-order/duplicate frames are ignored, not errors).
    sequence_number: u64,
    /// Max ack-eliciting packets the recipient may receive without sending an
    /// ACK.  0 = acknowledge every ack-eliciting packet; 1 = RFC 9000 default
    /// (every second packet).
    ack_eliciting_threshold: u64,
    /// Requested max_ack_delay in MICROSECONDS.  MUST be >= the receiving
    /// endpoint's advertised min_ack_delay or the connection errors with
    /// PROTOCOL_VIOLATION (draft §4).
    request_max_ack_delay_us: u64,
    /// Out-of-order tolerance before an immediate ACK: 0 = reordering never
    /// elicits an immediate ACK; 1 = any reordering does (RFC 9000 default).
    reordering_threshold: u64,

    pub const ParseResult = struct {
        frame: AckFrequencyFrame,
        /// Bytes consumed from `buf` (frame body only — the type varint has
        /// already been consumed by the frame-loop dispatcher).
        consumed: usize,
    };

    /// Parse the frame body (after the type varint).
    pub fn parse(buf: []const u8) varint.DecodeError!ParseResult {
        var pos: usize = 0;
        const seq = try varint.decode(buf[pos..]);
        pos += seq.len;
        const thresh = try varint.decode(buf[pos..]);
        pos += thresh.len;
        const delay = try varint.decode(buf[pos..]);
        pos += delay.len;
        const reorder = try varint.decode(buf[pos..]);
        pos += reorder.len;
        return .{
            .frame = .{
                .sequence_number = seq.value,
                .ack_eliciting_threshold = thresh.value,
                .request_max_ack_delay_us = delay.value,
                .reordering_threshold = reorder.value,
            },
            .consumed = pos,
        };
    }

    /// Serialize including the leading type varint.  Returns bytes written.
    pub fn serialize(self: *const AckFrequencyFrame, buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
        var pos: usize = 0;
        const fields = [_]u64{
            ack_frequency_frame_type,
            self.sequence_number,
            self.ack_eliciting_threshold,
            self.request_max_ack_delay_us,
            self.reordering_threshold,
        };
        for (fields) |v| {
            const enc = try varint.encode(buf[pos..], v);
            pos += enc.len;
        }
        return pos;
    }
};

/// Serialize an IMMEDIATE_ACK frame (type only, no body).
pub fn serializeImmediateAck(buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
    const enc = try varint.encode(buf, immediate_ack_frame_type);
    return enc.len;
}

test "ack_frequency: serialize/parse round-trip" {
    const testing = std.testing;
    const f = AckFrequencyFrame{
        .sequence_number = 7,
        .ack_eliciting_threshold = 10,
        .request_max_ack_delay_us = 25_000,
        .reordering_threshold = 1,
    };
    var buf: [64]u8 = undefined;
    const n = try f.serialize(&buf);
    // Type 0xaf > 0x3f → 2-byte varint on the wire.
    try testing.expectEqual(@as(u8, 0x40), buf[0]);
    try testing.expectEqual(@as(u8, 0xaf), buf[1]);

    const ft = try varint.decode(buf[0..n]);
    try testing.expectEqual(ack_frequency_frame_type, ft.value);
    const r = try AckFrequencyFrame.parse(buf[ft.len..n]);
    try testing.expectEqual(f.sequence_number, r.frame.sequence_number);
    try testing.expectEqual(f.ack_eliciting_threshold, r.frame.ack_eliciting_threshold);
    try testing.expectEqual(f.request_max_ack_delay_us, r.frame.request_max_ack_delay_us);
    try testing.expectEqual(f.reordering_threshold, r.frame.reordering_threshold);
    try testing.expectEqual(n - ft.len, r.consumed);
}

test "ack_frequency: parse rejects truncated body" {
    const testing = std.testing;
    const f = AckFrequencyFrame{
        .sequence_number = 300, // 2-byte varint — truncation lands mid-field
        .ack_eliciting_threshold = 2,
        .request_max_ack_delay_us = 1000,
        .reordering_threshold = 0,
    };
    var buf: [64]u8 = undefined;
    const n = try f.serialize(&buf);
    const ft = try varint.decode(buf[0..n]);
    var cut = ft.len;
    while (cut < n) : (cut += 1) {
        try testing.expectError(error.BufferTooShort, AckFrequencyFrame.parse(buf[ft.len..cut]));
    }
}

test "ack_frequency: immediate ack is a single byte 0x1f" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const n = try serializeImmediateAck(&buf);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x1f), buf[0]);
}

/// IMMEDIATE_ACK has no fields; empty struct for the frame registry union.
pub const ImmediateAck = struct {};
