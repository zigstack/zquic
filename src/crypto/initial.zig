//! QUIC Initial packet crypto helpers (RFC 9001 §5).
//!
//! Combines key derivation and AEAD to encrypt/decrypt Initial packets
//! and apply/remove header protection.

const std = @import("std");
const keys = @import("keys.zig");
const aead = @import("aead.zig");

pub const InitialSecrets = keys.InitialSecrets;
pub const KeyMaterial = keys.KeyMaterial;

/// AEAD used for Handshake / 0-RTT / 1-RTT packets (RFC 9001 §5.3).
/// Initial packets always use AES-128-GCM regardless of the TLS cipher suite.
pub const PacketCipher = enum {
    aes128_gcm,
    aes256_gcm,
    chacha20_poly1305,
};

/// The number of bytes of ciphertext sampled for header protection (RFC 9001 §5.4.2).
pub const hp_sample_len = 16;

/// Offset from start of the encrypted payload to the HP sample.
/// The sample starts 4 bytes after the start of the packet number field.
/// Since the PN can be 1–4 bytes, we always sample at offset `max_pn_len(4)`.
pub const hp_sample_offset = 4;

/// Decompress a truncated packet number to the expected packet number range.
/// RFC 9000 §17.1: The packet number encoding reveals 8, 16, or 24 bits. The packet
/// number is between the largest packet number before this packet and the largest
/// possible value in the truncated encoding.
pub fn decompressPacketNumber(truncated_pn: u64, expected_pn: ?u64, pn_len_bits: u3) u64 {
    if (expected_pn == null) return truncated_pn;

    const expected = expected_pn.?;
    const pn_range: u64 = switch (pn_len_bits) {
        0 => 0x100, // 1 byte  = 256
        1 => 0x10000, // 2 bytes = 65536
        2 => 0x1000000, // 3 bytes = 16777216
        3 => 0x100000000, // 4 bytes = 4294967296
        else => 0x100,
    };

    // Reconstruct the packet number: highest bits from expected, lowest bits from wire
    const expected_next = expected + 1;
    const range_half = pn_range / 2;

    // The received packet number is in range [expected_next - range_half, expected_next + range_half)
    // If truncated_pn is in the lower half, add pn_range to get the correct value
    const candidate_pn = (expected_next & ~(pn_range - 1)) | truncated_pn;

    // Check if we need to adjust by ±pn_range
    // Handle underflow by checking if expected_next > range_half
    const lower_bound: u64 = if (expected_next > range_half) expected_next - range_half else 0;
    const upper_bound = expected_next + range_half;

    if (candidate_pn < lower_bound) {
        return candidate_pn + pn_range;
    }
    if (candidate_pn >= upper_bound) {
        return candidate_pn - pn_range;
    }
    return candidate_pn;
}

/// Minimum `pn_len` wire encoding (RFC 9000 §17.1) for a given packet number.
pub fn wirePacketNumberLen(pn: u64) u2 {
    if (pn < 0x100) return 0;
    if (pn < 0x10000) return 1;
    if (pn < 0x1000000) return 2;
    return 3;
}

/// Encrypt a QUIC Initial packet payload and apply header protection.
/// Initial packets always use AES-128-GCM (RFC 9001 §5.3).
pub fn protectInitialPacket(
    dst: []u8,
    header: []const u8,
    pn: u64,
    pn_len: u2,
    plaintext: []const u8,
    km: *const KeyMaterial,
) aead.AeadError!usize {
    return protectLongHeaderPacket(dst, header, pn, pn_len, plaintext, km, .aes128_gcm);
}

/// Encrypt a long-header (Handshake / 0-RTT) packet and apply header protection.
pub fn protectLongHeaderPacket(
    dst: []u8,
    header: []const u8,
    pn: u64,
    pn_len: u2,
    plaintext: []const u8,
    km: *const KeyMaterial,
    cipher: PacketCipher,
) aead.AeadError!usize {
    const actual_pn_len: usize = @as(usize, pn_len) + 1;
    const ct_and_tag_len = plaintext.len + 16;

    if (dst.len < header.len + actual_pn_len + ct_and_tag_len) return error.BufferTooSmall;

    @memcpy(dst[0..header.len], header);
    dst[0] &= ~@as(u8, 0x03);
    dst[0] |= @as(u8, pn_len);
    var pos = header.len;

    var pn_buf: [4]u8 = undefined;
    var i: usize = 0;
    while (i < actual_pn_len) : (i += 1) {
        pn_buf[actual_pn_len - 1 - i] = @truncate(pn >> @intCast(i * 8));
    }
    @memcpy(dst[pos .. pos + actual_pn_len], pn_buf[0..actual_pn_len]);
    pos += actual_pn_len;

    var aad_buf: [128]u8 = undefined;
    if (pos > aad_buf.len) return error.BufferTooSmall;
    @memcpy(aad_buf[0..pos], dst[0..pos]);
    const aad = aad_buf[0..pos];
    const nonce = aead.buildNonce(km.iv, pn);

    switch (cipher) {
        .aes128_gcm => try km.aes_ctx.encrypt(dst[pos .. pos + ct_and_tag_len], plaintext, aad, nonce),
        .aes256_gcm => try aead.encryptAes256Gcm(dst[pos .. pos + ct_and_tag_len], plaintext, aad, km.key32, nonce),
        .chacha20_poly1305 => try aead.encryptChaCha20Poly1305(dst[pos .. pos + ct_and_tag_len], plaintext, aad, km.key32, nonce),
    }
    pos += ct_and_tag_len;

    const pn_start = header.len;
    const sample_start = pn_start + hp_sample_offset;
    if (pos < sample_start + hp_sample_len) return error.BufferTooSmall;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, dst[sample_start .. sample_start + hp_sample_len]);

    const pn_bytes_slice = dst[pn_start .. pn_start + actual_pn_len];
    const first_byte_mask: u8 = if (header[0] & 0x80 != 0) 0x0f else 0x1f;
    switch (cipher) {
        .aes128_gcm, .aes256_gcm => {
            const mask = km.hp_ctx.hpMask(sample);
            dst[0] ^= mask[0] & first_byte_mask;
            for (pn_bytes_slice, 0..) |*b, mi| {
                b.* ^= mask[1 + mi];
            }
        },
        .chacha20_poly1305 => {
            aead.HeaderProtection.applyChaCha20(km.hp32, sample, &dst[0], pn_bytes_slice, first_byte_mask);
        },
    }

    return pos;
}

/// Result of decrypting a long-header (Initial / Handshake) packet.
pub const UnprotectResult = struct {
    /// Decrypted plaintext length written into `dst`.
    pt_len: usize,
    /// Fully reconstructed (not truncated) packet number, suitable for use in
    /// ACK frames and the receive PN tracking table. Computed via
    /// `decompressPacketNumber` against `expected_recv_pn`.
    pn: u64,
};

/// Remove header protection from an Initial / Handshake packet and decrypt
/// its payload.
///
/// `buf` contains the full received packet. `pn_start` is the byte offset of
/// the start of the (protected) packet number. `km` is the key material for
/// the decrypting side. `dst` receives the decrypted plaintext.
/// `expected_recv_pn` is the largest packet number this connection has
/// already received at this encryption level, used to decompress the
/// truncated wire packet number per RFC 9000 §17.1.
///
/// Returns the plaintext length AND the reconstructed full packet number.
pub fn unprotectInitialPacket(
    dst: []u8,
    buf: []const u8,
    pn_start: usize,
    payload_end: usize,
    km: *const KeyMaterial,
    expected_recv_pn: ?u64,
) (aead.AeadError || error{BufferTooShort})!UnprotectResult {
    return unprotectLongHeaderPacket(dst, buf, pn_start, payload_end, km, expected_recv_pn, .aes128_gcm);
}

pub fn unprotectLongHeaderPacket(
    dst: []u8,
    buf: []const u8,
    pn_start: usize,
    payload_end: usize,
    km: *const KeyMaterial,
    expected_recv_pn: ?u64,
    cipher: PacketCipher,
) (aead.AeadError || error{BufferTooShort})!UnprotectResult {
    if (buf.len < pn_start + hp_sample_offset + hp_sample_len) return error.BufferTooShort;

    // Sample for header protection removal
    const sample_start = pn_start + hp_sample_offset;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, buf[sample_start .. sample_start + hp_sample_len]);

    // Compute HP mask and unmask first byte to discover PN length.
    const first_byte_mask: u8 = if (buf[0] & 0x80 != 0) 0x0f else 0x1f;
    const unmasked_first: u8 = switch (cipher) {
        .aes128_gcm, .aes256_gcm => blk: {
            const mask = km.hp_ctx.hpMask(sample);
            break :blk buf[0] ^ (mask[0] & first_byte_mask);
        },
        .chacha20_poly1305 => blk: {
            const counter = std.mem.readInt(u32, sample[0..4], .little);
            const cc_nonce = sample[4..16].*;
            var full_mask: [64]u8 = undefined;
            std.crypto.stream.chacha.ChaCha20IETF.xor(&full_mask, &(.{0} ** 64), counter, km.hp32, cc_nonce);
            break :blk buf[0] ^ (full_mask[0] & first_byte_mask);
        },
    };
    const actual_pn_len: usize = (unmasked_first & 0x03) + 1;

    const aad_end = pn_start + actual_pn_len;
    var aad_buf: [128]u8 = undefined;
    if (aad_end > aad_buf.len or aad_end > buf.len) return error.BufferTooShort;
    @memcpy(aad_buf[0..aad_end], buf[0..aad_end]);

    switch (cipher) {
        .aes128_gcm, .aes256_gcm => {
            const mask = km.hp_ctx.hpMask(sample);
            aad_buf[0] ^= mask[0] & first_byte_mask;
            for (aad_buf[pn_start..aad_end], 1..) |*b, mi| {
                b.* ^= mask[mi];
            }
        },
        .chacha20_poly1305 => {
            const counter = std.mem.readInt(u32, sample[0..4], .little);
            const cc_nonce = sample[4..16].*;
            var full_mask: [64]u8 = undefined;
            std.crypto.stream.chacha.ChaCha20IETF.xor(&full_mask, &(.{0} ** 64), counter, km.hp32, cc_nonce);
            aad_buf[0] ^= full_mask[0] & first_byte_mask;
            for (aad_buf[pn_start..aad_end], 1..) |*b, mi| {
                b.* ^= full_mask[mi];
            }
        },
    }

    // Decode the truncated wire PN, then reconstruct the full PN per RFC 9000
    // §17.1.  Using only the unmasked truncated bytes as the PN — as a prior
    // version of this code did — generates ACK frames that quote unsent packet
    // numbers (e.g. when the wire PN is 0x00 the AEAD nonce is right but the
    // ACK frame names PN 0x00 even after the connection PN advances), which
    // peers correctly reject as a PROTOCOL_VIOLATION ("unsent packet acked").
    var truncated_pn: u64 = 0;
    for (aad_buf[pn_start..aad_end]) |b| {
        truncated_pn = (truncated_pn << 8) | b;
    }
    const pn_len_bits: u3 = @intCast(actual_pn_len - 1);
    const pn = decompressPacketNumber(truncated_pn, expected_recv_pn, pn_len_bits);

    const aad = aad_buf[0..aad_end];
    const nonce = aead.buildNonce(km.iv, pn);
    const ciphertext = buf[aad_end..payload_end];

    if (ciphertext.len < 16) return error.BufferTooShort;
    const plaintext_len = ciphertext.len - 16;
    if (dst.len < plaintext_len) return error.BufferTooSmall;

    switch (cipher) {
        .aes128_gcm => try km.aes_ctx.decrypt(dst[0..plaintext_len], ciphertext, aad, nonce),
        .aes256_gcm => try aead.decryptAes256Gcm(dst[0..plaintext_len], ciphertext, aad, km.key32, nonce),
        .chacha20_poly1305 => try aead.decryptChaCha20Poly1305(dst[0..plaintext_len], ciphertext, aad, km.key32, nonce),
    }
    return .{ .pt_len = plaintext_len, .pn = pn };
}

/// Encrypt a QUIC 1-RTT packet payload using ChaCha20-Poly1305 and apply
/// ChaCha20-based header protection (RFC 9001 §5.3, §5.4.4).
pub fn protectPacketChaCha20(
    dst: []u8,
    header: []const u8,
    pn: u64,
    pn_len: u2,
    plaintext: []const u8,
    km: *const KeyMaterial,
) aead.AeadError!usize {
    const actual_pn_len: usize = @as(usize, pn_len) + 1;
    const ct_and_tag_len = plaintext.len + 16; // Poly1305 tag

    if (dst.len < header.len + actual_pn_len + ct_and_tag_len) return error.BufferTooSmall;

    @memcpy(dst[0..header.len], header);
    var pos = header.len;

    var pn_buf: [4]u8 = undefined;
    var i: usize = 0;
    while (i < actual_pn_len) : (i += 1) {
        pn_buf[actual_pn_len - 1 - i] = @truncate(pn >> @intCast(i * 8));
    }
    @memcpy(dst[pos .. pos + actual_pn_len], pn_buf[0..actual_pn_len]);
    pos += actual_pn_len;

    const aad_slice = dst[0..pos];
    const nonce = aead.buildNonce(km.iv, pn);

    try aead.encryptChaCha20Poly1305(dst[pos .. pos + ct_and_tag_len], plaintext, aad_slice, km.key32, nonce);
    pos += ct_and_tag_len;

    const pn_start = header.len;
    const sample_start = pn_start + hp_sample_offset;
    if (pos < sample_start + hp_sample_len) return error.BufferTooSmall;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, dst[sample_start .. sample_start + hp_sample_len]);

    const pn_bytes_slice = dst[pn_start .. pn_start + actual_pn_len];
    const first_byte_mask: u8 = if (dst[0] & 0x80 != 0) 0x0f else 0x1f;
    aead.HeaderProtection.applyChaCha20(km.hp32, sample, &dst[0], pn_bytes_slice, first_byte_mask);

    return pos;
}

/// Remove ChaCha20-based header protection and decrypt a QUIC packet payload.
pub fn unprotectPacketChaCha20(
    dst: []u8,
    buf: []const u8,
    pn_start: usize,
    payload_end: usize,
    km: *const KeyMaterial,
) (aead.AeadError || error{BufferTooShort})!usize {
    if (buf.len < pn_start + hp_sample_offset + hp_sample_len) return error.BufferTooShort;

    const sample_start = pn_start + hp_sample_offset;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, buf[sample_start .. sample_start + hp_sample_len]);

    const first_byte_mask: u8 = if (buf[0] & 0x80 != 0) 0x0f else 0x1f;

    // Derive ChaCha20 mask: counter = sample[0..4], nonce = sample[4..16]
    const counter = std.mem.readInt(u32, sample[0..4], .little);
    const cc_nonce = sample[4..16].*;
    var full_mask: [64]u8 = undefined;
    std.crypto.stream.chacha.ChaCha20IETF.xor(&full_mask, &(.{0} ** 64), counter, km.hp32, cc_nonce);

    const unmasked_first = buf[0] ^ (full_mask[0] & first_byte_mask);
    const actual_pn_len: usize = (unmasked_first & 0x03) + 1;

    // Copy only the header bytes needed for AAD (replaces the 1600-byte full-packet copy).
    const aad_end = pn_start + actual_pn_len;
    var aad_buf: [128]u8 = undefined;
    if (aad_end > aad_buf.len or aad_end > buf.len) return error.BufferTooShort;
    @memcpy(aad_buf[0..aad_end], buf[0..aad_end]);

    // Unmask first byte and PN bytes in the AAD copy.
    aad_buf[0] ^= full_mask[0] & first_byte_mask;
    for (aad_buf[pn_start..aad_end], 1..) |*b, mi| {
        b.* ^= full_mask[mi];
    }

    var pn: u64 = 0;
    for (aad_buf[pn_start..aad_end]) |b| {
        pn = (pn << 8) | b;
    }

    const aad_slice = aad_buf[0..aad_end];
    const nonce = aead.buildNonce(km.iv, pn);
    const ciphertext = buf[aad_end..payload_end];

    if (ciphertext.len < 16) return error.BufferTooShort;
    const plaintext_len = ciphertext.len - 16;
    if (dst.len < plaintext_len) return error.BufferTooSmall;

    try aead.decryptChaCha20Poly1305(dst[0..plaintext_len], ciphertext, aad_slice, km.key32, nonce);
    return plaintext_len;
}

test "initial: AES-256-GCM long-header round-trip" {
    const testing = std.testing;
    var km: KeyMaterial = .{ .secret = [_]u8{0x77} ** 32 };
    km.expand();

    const header = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x40, 0x10 };
    const plaintext = "handshake flight payload";

    var dst: [512]u8 = undefined;
    const written = try protectLongHeaderPacket(&dst, &header, 0, 0, plaintext, &km, .aes256_gcm);
    var decrypted: [128]u8 = undefined;
    const dec = try unprotectLongHeaderPacket(
        &decrypted,
        dst[0..written],
        header.len,
        written,
        &km,
        null,
        .aes256_gcm,
    );
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..dec.pt_len]);
}

test "initial: encrypt/decrypt round-trip" {
    const testing = std.testing;
    const dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
    const secrets = InitialSecrets.derive(dcid);

    // Fake header: first byte 0xc0 = LongHeader|FixedBit|Initial|PN_len=0 (1-byte PN)
    const header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00 };
    const plaintext = "test quic payload data";

    var dst: [512]u8 = undefined;
    const written = try protectInitialPacket(
        &dst,
        &header,
        0, // pn = 0
        0, // pn_len wire = 0 → 1 byte
        plaintext,
        &secrets.client,
    );
    try testing.expect(written > header.len + 1 + plaintext.len);

    // Decrypt
    var decrypted: [128]u8 = undefined;
    const pn_start = header.len;
    const payload_end = written;
    const dec = try unprotectInitialPacket(&decrypted, dst[0..written], pn_start, payload_end, &secrets.client, null);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..dec.pt_len]);
    try testing.expectEqual(@as(u64, 0), dec.pn);
}
