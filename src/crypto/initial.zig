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
        // Guard against overflow when adding pn_range (very high candidate_pn).
        if (candidate_pn > std.math.maxInt(u64) - pn_range) return candidate_pn;
        return candidate_pn + pn_range;
    }
    if (candidate_pn >= upper_bound) {
        // Guard against underflow: only subtract pn_range when it actually
        // fits.  RFC 9000 Appendix A's reconstruction algorithm assumes
        // candidate_pn ≥ pn_range here, but in early-handshake / many-conn
        // scenarios the candidate can be less than pn_range — in which case
        // the subtraction would trap on integer overflow.  Falling back to
        // candidate_pn is the conservative choice (the AEAD will then catch
        // any wrong-PN guess as a decrypt failure).
        if (candidate_pn < pn_range) return candidate_pn;
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
        // AES-128 HP: cached 16-byte AES context (built from `km.hp` at
        // `initCachedContexts` time).
        .aes128_gcm => {
            const mask = km.hp_ctx.hpMask(sample);
            dst[0] ^= mask[0] & first_byte_mask;
            for (pn_bytes_slice, 0..) |*b, mi| {
                b.* ^= mask[1 + mi];
            }
        },
        // AES-256 HP: RFC 9001 §5.4.3 — "Header protection has the same
        // key length as the packet protection key."  Must use AES-256 over
        // `km.hp32` (32 bytes), not the 16-byte cached AES-128 context.
        // Prior to this fix, AES-256-negotiated connections silently
        // applied HP under AES-128 with the truncated key — a wire-level
        // bug that would fail to interop with any spec-compliant peer.
        .aes256_gcm => {
            const ctx = std.crypto.core.aes.Aes256.initEnc(km.hp32);
            var mask: [16]u8 = undefined;
            ctx.encrypt(&mask, &sample);
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

    // Compute the 16-byte HP mask once up front under the negotiated
    // cipher (RFC 9001 §5.4).  Pre-fix, the AES-128 and AES-256 arms
    // both used the 16-byte cached AES-128 context — see the matching
    // §5.4.3 note in `protectLongHeaderPacket` for the wire-level bug.
    const hp_mask: [16]u8 = switch (cipher) {
        .aes128_gcm => km.hp_ctx.hpMask(sample),
        .aes256_gcm => blk: {
            const ctx = std.crypto.core.aes.Aes256.initEnc(km.hp32);
            var m: [16]u8 = undefined;
            ctx.encrypt(&m, &sample);
            break :blk m;
        },
        .chacha20_poly1305 => blk: {
            const counter = std.mem.readInt(u32, sample[0..4], .little);
            const cc_nonce = sample[4..16].*;
            var full_mask: [64]u8 = undefined;
            std.crypto.stream.chacha.ChaCha20IETF.xor(&full_mask, &(.{0} ** 64), counter, km.hp32, cc_nonce);
            var m: [16]u8 = undefined;
            @memcpy(&m, full_mask[0..16]);
            break :blk m;
        },
    };

    const first_byte_mask: u8 = if (buf[0] & 0x80 != 0) 0x0f else 0x1f;
    const unmasked_first: u8 = buf[0] ^ (hp_mask[0] & first_byte_mask);
    const actual_pn_len: usize = (unmasked_first & 0x03) + 1;

    const aad_end = pn_start + actual_pn_len;
    var aad_buf: [128]u8 = undefined;
    if (aad_end > aad_buf.len or aad_end > buf.len) return error.BufferTooShort;
    @memcpy(aad_buf[0..aad_end], buf[0..aad_end]);

    aad_buf[0] ^= hp_mask[0] & first_byte_mask;
    for (aad_buf[pn_start..aad_end], 1..) |*b, mi| {
        b.* ^= hp_mask[mi];
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

test "initial: AES-256 HP actually uses hp32 (regression for §5.4.3 violation)" {
    // RFC 9001 §5.4.3: "Header protection has the same key length as the
    // packet protection key."  Before this fix, both the AES-128 and
    // AES-256 cipher arms in `protect/unprotectLongHeaderPacket` derived
    // the HP mask via `km.hp_ctx.hpMask(sample)` — i.e. AES-128 over the
    // 16-byte `km.hp` field — for both ciphers.  Round-trip tests didn't
    // catch the divergence because both sides shared the broken impl.
    //
    // This test pins the wire format: under .aes256_gcm, the HP mask is
    // computed as AES-256-ECB(km.hp32, sample) — the same primitive a
    // spec-compliant peer would apply on decrypt.  We synthesize a
    // KeyMaterial where `km.hp` (16 bytes) and `km.hp32[0..16]` differ,
    // encrypt, then manually reproduce the AES-256 HP and verify the
    // protected first byte matches.

    const testing = std.testing;
    var km: KeyMaterial = .{ .secret = [_]u8{0x55} ** 32 };
    km.expand();
    // Deliberately desync hp vs hp32 so the buggy AES-128(hp) path would
    // produce a different mask than the correct AES-256(hp32) path.
    km.hp = [_]u8{0xCC} ** 16;
    @memset(&km.hp32, 0xAA);
    km.initCachedContexts();

    const header = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x40, 0x10 };
    const plaintext = "aes256 hp test payload";

    var dst: [512]u8 = undefined;
    const written = try protectLongHeaderPacket(&dst, &header, 0, 0, plaintext, &km, .aes256_gcm);

    // Reproduce the §5.4.2 HP sample: 4 bytes past the start of the PN,
    // 16 bytes long.  pn_start = header.len (we passed pn_len_wire = 0,
    // i.e. 1-byte PN).
    const pn_start: usize = header.len;
    const sample_start = pn_start + hp_sample_offset;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, dst[sample_start .. sample_start + hp_sample_len]);

    // Expected mask under AES-256-ECB(km.hp32, sample).
    var expected_mask: [16]u8 = undefined;
    const ctx = std.crypto.core.aes.Aes256.initEnc(km.hp32);
    ctx.encrypt(&expected_mask, &sample);

    // Long header → low-nibble mask (0x0f).  The protected first byte must
    // equal the plain first byte XOR'd with the AES-256 mask byte.
    const expected_first = header[0] ^ (expected_mask[0] & 0x0f);
    try testing.expectEqual(expected_first, dst[0]);

    // And it must NOT equal what the old (buggy) AES-128(km.hp) path
    // would have produced — that's the regression we're locking in.
    const wrong_mask = km.hp_ctx.hpMask(sample);
    const wrong_first = header[0] ^ (wrong_mask[0] & 0x0f);
    try testing.expect(dst[0] != wrong_first);

    // And round-trip still works (asymmetric correctness implied by the
    // oracle check above, but a positive end-to-end signal is cheap).
    var decrypted: [128]u8 = undefined;
    const dec = try unprotectLongHeaderPacket(&decrypted, dst[0..written], pn_start, written, &km, null, .aes256_gcm);
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

test "initial: decrypt real ngtcp2 (lantern) ClientHello with 4-byte Length varint" {
    // Captured from a c-lean-libp2p / ngtcp2 client (lantern v0.0.5) dialing a
    // zquic server.  The Length field uses a 4-byte varint encoding (0x80 00 04 94)
    // for value 1172, which is RFC-compliant non-minimum encoding and is what
    // aioquic / quinn correctly decrypt.  zquic's server-side AEAD was silently
    // rejecting these Initials, causing zeam to drop every dial attempt from
    // lantern with `server Initial AEAD/header-protection failed:
    // AuthenticationFailed dcid_len=8 pn_start=28 payload_len=1172`.
    //
    // DCID = e9b1ca4aeeb36102, version = 0x00000001, PN = 0, pn_len = 1.
    // Expected first plaintext byte = 0x06 (CRYPTO frame).
    const testing = std.testing;
    const raw_hex = "cb0000000108e9b1ca4aeeb3610208b924218da9ba10b100800004944bdab836d1f16b3fdfddb89f5d30b8ddd7e008cda49ec7d9ad878744b364866b1f24f1de932e26ec22c89b81dfb8afc219dd171914c06003d043a9961f86f217a141e807265d1f1c677b715418675fb08d5d68f8abf145553b03958c400ea01173217a55dec520dbe1874096530195ef7dd6662992274fae0f92d8e2b5e850beb10611a8329fe01eed5558de50232258226724e5176920b3b75582642a8c09f275365a424553b3d0adec10a156be26ed16839df644e0fba5406159a721567305d0cfeb88e4dcaf42d22a747062738429a472c46e991d40df3523f1abc4ddf7aaf13500f210029b46237a1be2ced837d5235230d0f8e03930b1c8618cf128deb0a77a0a4a3306445ce871b57734a7864923121961e401a0b82bf5ff4668b2795780007b08052d52b54e15d9a51a289bebcb9a3c086c32949716076ab5ba075277a55ca054d5c43fc2667cdbac2460d295a05e05b31f75b7ac29a43d8beaec136892cd3f6748557c5e1232a3e03700afad842d905f58ddc17dae2b2a0a8a7b3af1cfa32e19954f90b6a8adea01174e7e6fa65e82dc2302d38734d2b5f8dbc098d1a6b51d15f9279021080cca8247f919a94abeaa992b5a37b402fae99e7f89a86b704043c503f21520495c268b80dfb103b8e46e2dc6949b7db108e9c94ad8c79ec3bb13d71b34361582e27a3dfaef8044d65c4137471a35d82b6d320b40226689ad2df0e6771e6ed1ee33897c4efc809b77ca14c78556d8047ec43743f07efe5f534a399824d418ea725ec83993bcee5230e26197e484f59d6cf424b80eccc1977357189fa0aa5688fa39f1e83fa232ca02eea6ef71e5ecdc66cd47831d4cb246921ea6ee3b876740d95bd87e3246905cbc6c3fb2d3ba5f4f61dc695b20fbc506ab07a523bfbd621018803e1f8beccddd7fbeed2448dfd16c266bdaeb1af38f91cc4b9330e477a4d8f8fc8984a3d3ef64d1123b4ed6c9a4e233f1082095f92316779a9749e3265f06ab0883f3679283de7ec930dc85e3e000d6fb18f727c165461d4d06088b39544e2f5f89499f366b304c5f3987e07db6f3033dcd4546612d3aac41287290026e44292b334b09b540e3f6e9d4f7807be9e60bf743aefeaafb93eddae488b1dadf0ccbade3b1d1034e632aae64ba59bc7338fcbe06e050d036c0562395f1648fe07abb6b3bf21b140b188df2e74f9fffcdba7b91ff9f4e0ba3a88637c01e5e37e60d89481ed6f2610750e354d6b4985f3bbe4b0b3b247c640d84a19458a1759c09af2439a38a210911dc9df1427a7c87290bfc2a06530a7883142e7ef8fb681488e8ea173306fa7370a1a3d03c8ffbc0a9a9d9e4b26d996aaf58515b983d524760494bcc8769c789864a5f8d1cb663a2ba3e6f65f2ba11e1fa8519b847da4b04ac2d17cfbc6650c65e5c8a0121590848d629b976a15708f9ea157e99756ff0c95c0b021cb26190147c75d6b9bcaa0814cd4602c19adf6e4cec26015a75447688fb51b3aa42bfccda4b91b31886b4a5231beca1a03d4a83e57d3bf63e8ba310b96a23011774e7b06c06183e0a126e1fdfb3920818a76795690a1514f960f5bff3d9be6bd96d7e8c64862b1248bd27ff3a92d7ddb70e43ea48e17b6922bd0e7104a54b13a4db2479a8adc01aff1ec0";
    var raw: [1500]u8 = undefined;
    var i: usize = 0;
    while (i < raw_hex.len / 2) : (i += 1) {
        raw[i] = try std.fmt.parseInt(u8, raw_hex[i * 2 .. i * 2 + 2], 16);
    }
    const pkt = raw[0 .. raw_hex.len / 2];

    const dcid = "\xe9\xb1\xca\x4a\xee\xb3\x61\x02";
    const secrets = InitialSecrets.derive(dcid);

    // Header layout: flags(1)+ver(4)+dcidlen(1)+dcid(8)+scidlen(1)+scid(8)+tok_len(1)+len(4 byte varint) = 28
    const pn_start: usize = 28;
    const payload_len: usize = 1172;

    var pt: [4096]u8 = undefined;
    const dec = try unprotectInitialPacket(&pt, pkt, pn_start, pn_start + payload_len, &secrets.client, null);
    try testing.expectEqual(@as(u64, 0), dec.pn);
    try testing.expect(dec.pt_len > 0);
    // First plaintext byte must be a CRYPTO frame (0x06).
    try testing.expectEqual(@as(u8, 0x06), pt[0]);
}
