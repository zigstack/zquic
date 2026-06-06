//! All QUIC packet types: Initial, Handshake, 0-RTT, Retry, Version Negotiation,
//! and 1-RTT (short header). Provides high-level parse/build helpers.
//!
//! Packet layout overview (before encryption):
//!   Initial / Handshake / 0-RTT (Long):
//!     [Long Header] [Token (Initial only)] [Length (varint)] [PN (1-4 B)] [Payload]
//!   Retry (Long):
//!     [Long Header] [Token] [Retry Integrity Tag (16 B)]
//!   Version Negotiation:
//!     [First Byte] [Version=0] [DCID Len+DCID] [SCID Len+SCID] [Supported Versions…]
//!   1-RTT (Short):
//!     [Short Header] [PN (1-4 B)] [Payload]

const std = @import("std");
const types = @import("../types.zig");
const varint = @import("../varint.zig");
const header = @import("header.zig");

pub const ConnectionId = types.ConnectionId;
pub const Version = types.Version;
pub const LongType = header.LongType;

pub const ParseError = header.ParseError || varint.DecodeError || error{ InvalidPacket, TooLong };

/// Parsed Initial packet fields (after long header).
pub const InitialPacket = struct {
    dcid: ConnectionId,
    scid: ConnectionId,
    token: []const u8,
    /// Byte offset of the start of the encrypted payload (PN + payload).
    payload_offset: usize,
    /// Number of bytes in (PN + payload), as encoded in the Length field.
    payload_len: usize,
};

/// Parsed Retry packet.
pub const RetryPacket = struct {
    dcid: ConnectionId,
    scid: ConnectionId,
    /// Retry token (everything between header and integrity tag).
    token: []const u8,
    /// The 16-byte AES-128-GCM integrity tag.
    integrity_tag: [16]u8,
};

/// Parsed Version Negotiation packet.
pub const VersionNegotiationPacket = struct {
    dcid: ConnectionId,
    scid: ConnectionId,
    /// Supported version list (each 4 bytes, may be empty).
    versions: []const u8,
};

/// Parse an Initial packet from `buf` (buf[0] must be the first byte).
pub fn parseInitial(buf: []const u8) ParseError!InitialPacket {
    const lh = try header.parseLong(buf);
    if (lh.header.packet_type != .initial) return error.InvalidPacket;
    var pos = lh.consumed;

    // Token length + token
    if (pos >= buf.len) return error.BufferTooShort;
    const tok_len_r = try varint.decodePermissive(buf[pos..]);
    pos += tok_len_r.len;
    const tok_len: usize = @intCast(tok_len_r.value);
    if (pos + tok_len > buf.len) return error.BufferTooShort;
    const token = buf[pos .. pos + tok_len];
    pos += tok_len;

    // Length (covers PN + payload)
    if (pos >= buf.len) return error.BufferTooShort;
    const payload_len_r = try varint.decodePermissive(buf[pos..]);
    pos += payload_len_r.len;
    const payload_len: usize = @intCast(payload_len_r.value);

    if (pos + payload_len > buf.len) return error.BufferTooShort;

    return .{
        .dcid = lh.header.dcid,
        .scid = lh.header.scid,
        .token = token,
        .payload_offset = pos,
        .payload_len = payload_len,
    };
}

/// Parse a Retry packet from `buf`.
pub fn parseRetry(buf: []const u8) ParseError!RetryPacket {
    const lh = try header.parseLong(buf);
    if (lh.header.packet_type != .retry) return error.InvalidPacket;
    const pos = lh.consumed;

    // Everything after the header and before the last 16 bytes is the token.
    if (buf.len < pos + 16) return error.BufferTooShort;
    const token = buf[pos .. buf.len - 16];
    var tag: [16]u8 = undefined;
    @memcpy(&tag, buf[buf.len - 16 ..]);

    return .{
        .dcid = lh.header.dcid,
        .scid = lh.header.scid,
        .token = token,
        .integrity_tag = tag,
    };
}

/// Parse a Version Negotiation packet from `buf`.
pub fn parseVersionNegotiation(buf: []const u8) ParseError!VersionNegotiationPacket {
    if (buf.len < 7) return error.BufferTooShort;
    // VN has version = 0x00000000 and may have any first byte with bit 7 set.
    // Check version field.
    if (buf[0] & 0x40 == 0) return error.InvalidFixedBit;
    const version = std.mem.readInt(u32, buf[1..5], .big);
    if (version != 0x00000000) return error.InvalidPacket;

    var pos: usize = 5;
    const dcid_len = buf[pos];
    pos += 1;
    if (pos + dcid_len > buf.len) return error.BufferTooShort;
    const dcid = try ConnectionId.fromSlice(buf[pos .. pos + dcid_len]);
    pos += dcid_len;

    if (pos >= buf.len) return error.BufferTooShort;
    const scid_len = buf[pos];
    pos += 1;
    if (pos + scid_len > buf.len) return error.BufferTooShort;
    const scid = try ConnectionId.fromSlice(buf[pos .. pos + scid_len]);
    pos += scid_len;

    // Remaining bytes are supported version list (4-byte each).
    const versions = buf[pos..];

    return .{
        .dcid = dcid,
        .scid = scid,
        .versions = versions,
    };
}

/// Determine whether `buf` looks like a long-header packet.
pub fn isLongHeader(buf: []const u8) bool {
    if (buf.len == 0) return false;
    return (buf[0] & 0x80) != 0;
}

/// Determine whether `buf` looks like a Version Negotiation packet.
pub fn isVersionNegotiation(buf: []const u8) bool {
    if (buf.len < 5) return false;
    if (buf[0] & 0x80 == 0) return false;
    return std.mem.readInt(u32, buf[1..5], .big) == 0;
}

/// Build an Initial packet header into `buf` (without encryption).
/// Returns bytes written (header only; caller appends PN + payload).
pub fn buildInitialHeader(
    buf: []u8,
    version: u32,
    dcid: ConnectionId,
    scid: ConnectionId,
    token: []const u8,
    payload_len: usize,
    pn_len: u2,
) (header.ParseError || varint.EncodeError || varint.DecodeError)!usize {
    // First byte: Header Form=1, Fixed Bit=1, Type=Initial (00), Reserved=00, PN Len
    buf[0] = 0xc0 | @as(u8, pn_len);
    std.mem.writeInt(u32, buf[1..5], version, .big);
    var pos: usize = 5;

    buf[pos] = dcid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + dcid.len], dcid.slice());
    pos += dcid.len;

    buf[pos] = scid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + scid.len], scid.slice());
    pos += scid.len;

    // Token
    const tok_enc = try varint.encode(buf[pos..], token.len);
    pos += tok_enc.len;
    @memcpy(buf[pos .. pos + token.len], token);
    pos += token.len;

    // Length = pn_len + 1 + payload_len
    const length_field = @as(u64, pn_len) + 1 + payload_len;
    const len_enc = try varint.encode(buf[pos..], length_field);
    pos += len_enc.len;

    return pos;
}

/// Build a Version Negotiation packet into `buf`. Returns bytes written.
pub fn buildVersionNegotiation(
    buf: []u8,
    dcid: ConnectionId,
    scid: ConnectionId,
    supported: []const u32,
) error{BufferTooShort}!usize {
    const needed = 1 + 4 + 1 + dcid.len + 1 + scid.len + supported.len * 4;
    if (buf.len < needed) return error.BufferTooShort;

    // First byte: Header Form=1, Fixed Bit=1, random lower bits
    buf[0] = 0xcf;
    std.mem.writeInt(u32, buf[1..5], 0x00000000, .big); // version = 0
    var pos: usize = 5;

    buf[pos] = dcid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + dcid.len], dcid.slice());
    pos += dcid.len;

    buf[pos] = scid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + scid.len], scid.slice());
    pos += scid.len;

    for (supported) |v| {
        std.mem.writeInt(u32, buf[pos..][0..4], v, .big);
        pos += 4;
    }
    return pos;
}

test "packet: Initial parse" {
    const testing = std.testing;

    // Build a minimal Initial packet
    const dcid = try ConnectionId.fromSlice(&[_]u8{ 0x01, 0x02 });
    const scid = try ConnectionId.fromSlice(&[_]u8{0x03});
    var buf: [128]u8 = undefined;

    // Fake payload: 10 bytes; pn_len=0 → 1-byte PN on wire (length_field = 1 + 10 = 11)
    const fake_payload_len = 10;
    const pn_len_wire: u2 = 0; // wire encoding: 0 → 1 byte PN
    const pos = try buildInitialHeader(&buf, 0x00000001, dcid, scid, &.{}, fake_payload_len, pn_len_wire);
    // Fill fake PN (1 byte) + payload
    buf[pos] = 0x00;
    @memset(buf[pos + 1 .. pos + 1 + fake_payload_len], 0xAA);

    const pkt = try parseInitial(buf[0 .. pos + 1 + fake_payload_len]);
    try testing.expect(ConnectionId.eql(dcid, pkt.dcid));
    try testing.expect(ConnectionId.eql(scid, pkt.scid));
    try testing.expectEqual(@as(usize, 0), pkt.token.len);
    // length_field = pn_len_wire(0) + 1 + fake_payload_len(10) = 11
    try testing.expectEqual(@as(usize, 11), pkt.payload_len);
}

test "packet: Version Negotiation build/parse" {
    const testing = std.testing;

    const dcid = try ConnectionId.fromSlice(&[_]u8{ 0xAA, 0xBB });
    const scid = try ConnectionId.fromSlice(&[_]u8{0xCC});
    const supported = [_]u32{ 0x00000001, 0x6b3343cf };

    var buf: [64]u8 = undefined;
    const written = try buildVersionNegotiation(&buf, dcid, scid, &supported);

    try testing.expect(isVersionNegotiation(buf[0..written]));
    const pkt = try parseVersionNegotiation(buf[0..written]);
    try testing.expect(ConnectionId.eql(dcid, pkt.dcid));
    try testing.expect(ConnectionId.eql(scid, pkt.scid));
    try testing.expectEqual(@as(usize, 8), pkt.versions.len);
    try testing.expectEqual(@as(u32, 0x00000001), std.mem.readInt(u32, pkt.versions[0..4], .big));
    try testing.expectEqual(@as(u32, 0x6b3343cf), std.mem.readInt(u32, pkt.versions[4..8], .big));
}
