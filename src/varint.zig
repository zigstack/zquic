//! QUIC RFC 9000 §16 varint, sourced from
//! [`zig-varint`](https://github.com/ch4r10t33r/zig-varint).
//!
//! This file is a back-compat re-export so existing call sites keep
//! `@import("varint.zig")` and reference the same symbol names that the old
//! in-tree module exposed (`encode`, `decode`, `lenToUsize`, `Reader`,
//! `Writer`, `EncodeError`, `DecodeError`, `max_value`, `encodedLen`).

const std = @import("std");
const quic = @import("zig_varint").quic;

pub const max_value = quic.max_value;
pub const EncodeError = quic.EncodeError;
pub const DecodeError = quic.DecodeError;

pub const lenToUsize = quic.lenToUsize;
pub const encodedLen = quic.encodedLen;
pub const encode = quic.encode;
pub const decode = quic.decode;

/// Decode a peer varint without rejecting non-minimal encodings.
/// quinn has been observed to send e.g. `0x4019` for value 25 on coalesced
/// Initial retransmits; strict decode would skip the trailing Handshake packet.
pub fn decodePermissive(buf: []const u8) DecodeError!struct { value: u64, len: u4 } {
    if (buf.len == 0) return error.BufferTooShort;
    const prefix: u2 = @intCast(buf[0] >> 6);
    switch (prefix) {
        0b00 => return .{ .value = buf[0] & 0x3f, .len = 1 },
        0b01 => {
            if (buf.len < 2) return error.BufferTooShort;
            const w = std.mem.readInt(u16, buf[0..2], .big);
            return .{ .value = w & 0x3fff, .len = 2 };
        },
        0b10 => {
            if (buf.len < 4) return error.BufferTooShort;
            const w = std.mem.readInt(u32, buf[0..4], .big);
            return .{ .value = w & 0x3fffffff, .len = 4 };
        },
        0b11 => {
            if (buf.len < 8) return error.BufferTooShort;
            const w = std.mem.readInt(u64, buf[0..8], .big);
            return .{ .value = w & 0x3fffffffffffffff, .len = 8 };
        },
    }
}

pub const Reader = quic.Reader;
pub const Writer = quic.Writer;

test {
    _ = quic;
}

test "decodePermissive accepts non-minimal encodings that strict decode rejects" {
    // RFC 9000 §16 does not require minimal varint encoding.  ngtcp2 / quinn
    // emit non-minimal Length fields on coalesced Handshake packets: e.g. the
    // 2-byte form 0x40 0x19 encodes value 25, which also fits in a 1-byte
    // varint.  Strict `decode` rejects this as non-minimal; the receive path
    // (Handshake packet Length, CRYPTO offset/len) must use `decodePermissive`
    // or the trailing Handshake packet is silently dropped and the client
    // wedges in the Initial phase (the zeam<->lantern/ngtcp2 handshake bug).
    const non_minimal = [_]u8{ 0x40, 0x19 }; // 2-byte encoding of value 25
    const r = try decodePermissive(&non_minimal);
    try std.testing.expectEqual(@as(u64, 25), r.value);
    try std.testing.expectEqual(@as(u4, 2), r.len);

    // Strict decode rejects the same non-minimal encoding (or yields a
    // different result); decodePermissive is required to accept it verbatim.
    if (decode(&non_minimal)) |strict| {
        try std.testing.expect(strict.len != 2 or strict.value != 25);
    } else |_| {}
}
