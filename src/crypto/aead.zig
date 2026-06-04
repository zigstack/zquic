//! QUIC AEAD encryption/decryption and header protection (RFC 9001 §5.3–5.4).
//!
//! QUIC v1 uses AES-128-GCM for Initial and Handshake packets (default cipher
//! suite). ChaCha20-Poly1305 is also supported for interop. The header
//! protection algorithm uses the HP key to mask the first byte and packet
//! number bytes.

const std = @import("std");
const crypto = std.crypto;
const Aes128 = crypto.core.aes.Aes128;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const Ghash = crypto.onetimeauth.Ghash;
const modes = crypto.core.modes;

pub const AeadError = error{
    AuthenticationFailed,
    BufferTooSmall,
};

/// QUIC nonce construction: XOR IV with packet number (RFC 9001 §5.3).
/// The packet number is left-padded with zeros to match the IV length (12 bytes).
pub fn buildNonce(iv: [12]u8, packet_number: u64) [12]u8 {
    var nonce = iv;
    // XOR the last 8 bytes of the nonce with the packet number (big-endian)
    const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, packet_number));
    for (0..8) |i| {
        nonce[4 + i] ^= pn_bytes[i];
    }
    return nonce;
}

/// Encrypt plaintext in-place using AES-128-GCM, appending the 16-byte tag.
/// `dst` must have capacity for `plaintext.len + 16` bytes.
/// `aad` is the QUIC packet header bytes used as Additional Authenticated Data.
pub fn encryptAes128Gcm(
    dst: []u8,
    plaintext: []const u8,
    aad: []const u8,
    key: [16]u8,
    nonce: [12]u8,
) AeadError!void {
    if (dst.len < plaintext.len + Aes128Gcm.tag_length) return error.BufferTooSmall;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(dst[0..plaintext.len], &tag, plaintext, aad, nonce, key);
    @memcpy(dst[plaintext.len..][0..Aes128Gcm.tag_length], &tag);
}

/// Encrypt using AES-256-GCM (TLS_AES_256_GCM_SHA384 handshake / 1-RTT protection).
pub fn encryptAes256Gcm(
    dst: []u8,
    plaintext: []const u8,
    aad: []const u8,
    key: [32]u8,
    nonce: [12]u8,
) AeadError!void {
    if (dst.len < plaintext.len + Aes256Gcm.tag_length) return error.BufferTooSmall;
    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    Aes256Gcm.encrypt(dst[0..plaintext.len], &tag, plaintext, aad, nonce, key);
    @memcpy(dst[plaintext.len..][0..Aes256Gcm.tag_length], &tag);
}

/// Decrypt using AES-256-GCM.
pub fn decryptAes256Gcm(
    dst: []u8,
    ciphertext: []const u8,
    aad: []const u8,
    key: [32]u8,
    nonce: [12]u8,
) AeadError!void {
    if (ciphertext.len < Aes256Gcm.tag_length) return error.AuthenticationFailed;
    const ct = ciphertext[0 .. ciphertext.len - Aes256Gcm.tag_length];
    const tag = ciphertext[ciphertext.len - Aes256Gcm.tag_length ..][0..Aes256Gcm.tag_length];
    if (dst.len < ct.len) return error.BufferTooSmall;
    Aes256Gcm.decrypt(dst[0..ct.len], ct, tag.*, aad, nonce, key) catch return error.AuthenticationFailed;
}

/// Decrypt and authenticate ciphertext using AES-128-GCM.
/// `ciphertext` includes the 16-byte authentication tag at the end.
/// `dst` receives the plaintext (len = ciphertext.len - 16).
pub fn decryptAes128Gcm(
    dst: []u8,
    ciphertext: []const u8,
    aad: []const u8,
    key: [16]u8,
    nonce: [12]u8,
) AeadError!void {
    if (ciphertext.len < Aes128Gcm.tag_length) return error.AuthenticationFailed;
    const ct = ciphertext[0 .. ciphertext.len - Aes128Gcm.tag_length];
    const tag = ciphertext[ciphertext.len - Aes128Gcm.tag_length ..][0..Aes128Gcm.tag_length];
    if (dst.len < ct.len) return error.BufferTooSmall;
    Aes128Gcm.decrypt(dst[0..ct.len], ct, tag.*, aad, nonce, key) catch return error.AuthenticationFailed;
}

/// Encrypt using ChaCha20-Poly1305 (for interop chacha20 test case).
pub fn encryptChaCha20Poly1305(
    dst: []u8,
    plaintext: []const u8,
    aad: []const u8,
    key: [32]u8,
    nonce: [12]u8,
) AeadError!void {
    if (dst.len < plaintext.len + ChaCha20Poly1305.tag_length) return error.BufferTooSmall;
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    ChaCha20Poly1305.encrypt(dst[0..plaintext.len], &tag, plaintext, aad, nonce, key);
    @memcpy(dst[plaintext.len..][0..ChaCha20Poly1305.tag_length], &tag);
}

/// Decrypt using ChaCha20-Poly1305.
pub fn decryptChaCha20Poly1305(
    dst: []u8,
    ciphertext: []const u8,
    aad: []const u8,
    key: [32]u8,
    nonce: [12]u8,
) AeadError!void {
    if (ciphertext.len < ChaCha20Poly1305.tag_length) return error.AuthenticationFailed;
    const ct = ciphertext[0 .. ciphertext.len - ChaCha20Poly1305.tag_length];
    const tag = ciphertext[ciphertext.len - ChaCha20Poly1305.tag_length ..][0..ChaCha20Poly1305.tag_length];
    if (dst.len < ct.len) return error.BufferTooSmall;
    ChaCha20Poly1305.decrypt(dst[0..ct.len], ct, tag.*, aad, nonce, key) catch return error.AuthenticationFailed;
}

/// Header protection using AES-128-ECB (RFC 9001 §5.4.3).
///
/// The HP key encrypts a 16-byte sample taken from the packet ciphertext,
/// then the first 5 bytes of the result are XOR'd with the header bytes.
pub const HeaderProtection = struct {
    /// Apply (or remove) AES-128 header protection.
    /// `first_byte_mask` is bits 0x0f for long headers, 0x1f for short.
    pub fn applyAes128(
        hp_key: [16]u8,
        sample: [16]u8,
        header_first_byte: *u8,
        pn_bytes: []u8,
        first_byte_mask: u8,
    ) void {
        // AES-128-ECB encrypt the sample
        const ctx = Aes128.initEnc(hp_key);
        var mask: [16]u8 = undefined;
        ctx.encrypt(&mask, &sample);

        // Mask the first byte (protecting Type/Reserved/PN-length bits)
        header_first_byte.* ^= mask[0] & first_byte_mask;

        // Mask the packet number bytes
        for (pn_bytes, 0..) |*b, i| {
            b.* ^= mask[1 + i];
        }
    }

    /// Header protection for ChaCha20 (RFC 9001 §5.4.4).
    /// Uses ChaCha20 as a counter-mode cipher to derive the mask.
    pub fn applyChaCha20(
        hp_key: [32]u8,
        sample: [16]u8,
        header_first_byte: *u8,
        pn_bytes: []u8,
        first_byte_mask: u8,
    ) void {
        // counter = sample[0..4] (little-endian u32)
        // nonce = sample[4..16]
        const counter = std.mem.readInt(u32, sample[0..4], .little);
        const nonce = sample[4..16].*;
        var mask: [5]u8 = .{ 0, 0, 0, 0, 0 };
        // ChaCha20 keystream starting at block `counter`, byte 64 (second 64-byte block)
        // We use the standard chacha20 with a dedicated output
        var full_mask: [64]u8 = undefined;
        crypto.stream.chacha.ChaCha20IETF.xor(&full_mask, &(.{0} ** 64), counter, hp_key, nonce);
        @memcpy(&mask, full_mask[0..5]);

        header_first_byte.* ^= mask[0] & first_byte_mask;
        for (pn_bytes, 0..) |*b, i| {
            b.* ^= mask[1 + i];
        }
    }
};

/// Pre-expanded AES-128 context for AEAD and header protection.
///
/// Caches the AES key schedule so that `initEnc()` (10-round key expansion)
/// is performed once at key derivation time rather than on every packet.
/// On ARM this saves ~40 AES operations per encrypt/decrypt call.
///
/// AES-128-GCM is implemented by composing the standard library AES block cipher,
/// CTR mode, and GHASH — not by calling `Aes128Gcm` directly — so the expanded
/// key can be reused. That trades a larger audit surface for fewer per-packet
/// key schedules; the primitives are the usual `std.crypto` building blocks.
pub const CachedAes128Context = struct {
    const AesEncCtx = @TypeOf(Aes128.initEnc([_]u8{0} ** 16));
    const tag_length = 16;
    const nonce_length = 12;
    const zeros = [_]u8{0} ** 16;

    aes: AesEncCtx,

    pub fn init(key: [16]u8) CachedAes128Context {
        return .{ .aes = Aes128.initEnc(key) };
    }

    /// Encrypt plaintext using AES-128-GCM with the pre-expanded key schedule.
    /// `dst` must have capacity for `plaintext.len + 16` bytes.
    pub fn encrypt(
        self: *const CachedAes128Context,
        dst: []u8,
        plaintext: []const u8,
        aad: []const u8,
        nonce: [nonce_length]u8,
    ) AeadError!void {
        if (dst.len < plaintext.len + tag_length) return error.BufferTooSmall;
        const aes = self.aes;

        var h: [16]u8 = undefined;
        aes.encrypt(&h, &zeros);

        var t: [16]u8 = undefined;
        var j: [16]u8 = undefined;
        j[0..nonce_length].* = nonce;
        std.mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
        aes.encrypt(&t, &j);

        const ct = dst[0..plaintext.len];
        // Divisor is the 16-byte GHASH block (non-zero); divCeil only fails if divisor is 0.
        const block_count = (std.math.divCeil(usize, aad.len, Ghash.block_length) catch unreachable) +
            (std.math.divCeil(usize, ct.len, Ghash.block_length) catch unreachable) + 1;
        var mac = Ghash.initForBlockCount(&h, block_count);
        mac.update(aad);
        mac.pad();

        std.mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
        modes.ctr(@TypeOf(aes), aes, ct, plaintext, j, .big);
        mac.update(ct);
        mac.pad();

        var final_block = h;
        std.mem.writeInt(u64, final_block[0..8], @as(u64, aad.len) * 8, .big);
        std.mem.writeInt(u64, final_block[8..16], @as(u64, plaintext.len) * 8, .big);
        mac.update(&final_block);
        var tag: [tag_length]u8 = undefined;
        mac.final(&tag);
        for (t, 0..) |x, i| {
            tag[i] ^= x;
        }
        @memcpy(dst[plaintext.len..][0..tag_length], &tag);
    }

    /// Decrypt and authenticate ciphertext using AES-128-GCM with the pre-expanded key.
    /// `ciphertext` includes the 16-byte authentication tag at the end.
    pub fn decrypt(
        self: *const CachedAes128Context,
        dst: []u8,
        ciphertext: []const u8,
        aad: []const u8,
        nonce: [nonce_length]u8,
    ) AeadError!void {
        if (ciphertext.len < tag_length) return error.AuthenticationFailed;
        const ct = ciphertext[0 .. ciphertext.len - tag_length];
        const tag = ciphertext[ciphertext.len - tag_length ..][0..tag_length];
        if (dst.len < ct.len) return error.BufferTooSmall;
        const aes = self.aes;

        var h: [16]u8 = undefined;
        aes.encrypt(&h, &zeros);

        var t: [16]u8 = undefined;
        var j: [16]u8 = undefined;
        j[0..nonce_length].* = nonce;
        std.mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
        aes.encrypt(&t, &j);

        // Ghash.block_length is 16; divCeil only fails on divisor 0.
        const block_count = (std.math.divCeil(usize, aad.len, Ghash.block_length) catch unreachable) +
            (std.math.divCeil(usize, ct.len, Ghash.block_length) catch unreachable) + 1;
        var mac = Ghash.initForBlockCount(&h, block_count);
        mac.update(aad);
        mac.pad();

        mac.update(ct);
        mac.pad();

        var final_block = h;
        std.mem.writeInt(u64, final_block[0..8], @as(u64, aad.len) * 8, .big);
        std.mem.writeInt(u64, final_block[8..16], @as(u64, ct.len) * 8, .big);
        mac.update(&final_block);
        var computed_tag: [Ghash.mac_length]u8 = undefined;
        mac.final(&computed_tag);
        for (t, 0..) |x, i| {
            computed_tag[i] ^= x;
        }

        if (!crypto.timing_safe.eql([tag_length]u8, computed_tag, tag.*)) {
            crypto.secureZero(u8, &computed_tag);
            @memset(dst[0..ct.len], undefined);
            return error.AuthenticationFailed;
        }

        const m = dst[0..ct.len];
        std.mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
        modes.ctr(@TypeOf(aes), aes, m, ct, j, .big);
    }

    /// Compute the 16-byte header protection mask using the pre-expanded key.
    pub fn hpMask(self: *const CachedAes128Context, sample: [16]u8) [16]u8 {
        var mask: [16]u8 = undefined;
        self.aes.encrypt(&mask, &sample);
        return mask;
    }
};

test "aead: CachedAes128Context matches stdlib AES-128-GCM" {
    const testing = std.testing;
    const key: [16]u8 = .{0x01} ** 16;
    const nonce: [12]u8 = .{0x02} ** 12;
    const plaintext = "Hello, QUIC! Cached context test.";
    const aad = "header bytes";

    // Stdlib path
    var std_ct: [plaintext.len + 16]u8 = undefined;
    try encryptAes128Gcm(&std_ct, plaintext, aad, key, nonce);

    // Cached path
    const ctx = CachedAes128Context.init(key);
    var cached_ct: [plaintext.len + 16]u8 = undefined;
    try ctx.encrypt(&cached_ct, plaintext, aad, nonce);

    // Must produce identical ciphertext + tag
    try testing.expectEqualSlices(u8, &std_ct, &cached_ct);

    // Cached decrypt must recover plaintext
    var recovered: [plaintext.len]u8 = undefined;
    try ctx.decrypt(&recovered, &cached_ct, aad, nonce);
    try testing.expectEqualSlices(u8, plaintext, &recovered);
}

test "aead: CachedAes128Context HP mask matches HeaderProtection" {
    const testing = std.testing;
    const hp_key: [16]u8 = .{0xAB} ** 16;
    const sample: [16]u8 = .{0xCD} ** 16;

    // Stdlib HP path
    var first_std: u8 = 0xc3;
    var pn_std = [_]u8{ 0x01, 0x02 };
    HeaderProtection.applyAes128(hp_key, sample, &first_std, &pn_std, 0x0f);

    // Cached HP path
    const ctx = CachedAes128Context.init(hp_key);
    const mask = ctx.hpMask(sample);
    var first_cached: u8 = 0xc3;
    var pn_cached = [_]u8{ 0x01, 0x02 };
    first_cached ^= mask[0] & 0x0f;
    for (&pn_cached, 0..) |*b, i| {
        b.* ^= mask[1 + i];
    }

    try testing.expectEqual(first_std, first_cached);
    try testing.expectEqualSlices(u8, &pn_std, &pn_cached);
}

test "aead: AES-128-GCM encrypt/decrypt round-trip" {
    const testing = std.testing;
    const key: [16]u8 = .{0x01} ** 16;
    const nonce: [12]u8 = .{0x02} ** 12;
    const plaintext = "Hello, QUIC!";
    const aad = "header";

    var ciphertext: [plaintext.len + Aes128Gcm.tag_length]u8 = undefined;
    try encryptAes128Gcm(&ciphertext, plaintext, aad, key, nonce);

    var recovered: [plaintext.len]u8 = undefined;
    try decryptAes128Gcm(&recovered, &ciphertext, aad, key, nonce);
    try testing.expectEqualSlices(u8, plaintext, &recovered);
}

test "aead: AES-128-GCM auth failure on tampered ciphertext" {
    const key: [16]u8 = .{0x01} ** 16;
    const nonce: [12]u8 = .{0x02} ** 12;
    const plaintext = "Hello!";
    const aad = "hdr";

    var ciphertext: [plaintext.len + Aes128Gcm.tag_length]u8 = undefined;
    try encryptAes128Gcm(&ciphertext, plaintext, aad, key, nonce);
    ciphertext[0] ^= 0xff; // tamper

    var out: [plaintext.len]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, decryptAes128Gcm(&out, &ciphertext, aad, key, nonce));
}

test "aead: nonce construction XORs packet number" {
    const testing = std.testing;
    const iv = [12]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };
    // pn = 1: last byte of IV (0x0b) XOR 0x01 = 0x0a; byte 10 unchanged (0x0a XOR 0x00 = 0x0a)
    const nonce = buildNonce(iv, 1);
    try testing.expectEqual(@as(u8, 0x0a), nonce[10]);
    try testing.expectEqual(@as(u8, 0x0a), nonce[11]); // 0x0b XOR 0x01 = 0x0a
    // Bytes 0..3 are unchanged (IV is only 12 bytes, PN XOR affects bytes 4..11)
    try testing.expectEqual(@as(u8, 0x00), nonce[0]);
}

test "aead: RFC 9001 Appendix A header protection smoke test" {
    // Just verify the AES-128 HP mask derivation path runs without panic.
    const hp_key: [16]u8 = .{0xAB} ** 16;
    const sample: [16]u8 = .{0xCD} ** 16;
    var first: u8 = 0xc3;
    var pn = [_]u8{ 0x01, 0x02 };
    HeaderProtection.applyAes128(hp_key, sample, &first, &pn, 0x0f);
    // Apply again to unmask (HP is its own inverse)
    HeaderProtection.applyAes128(hp_key, sample, &first, &pn, 0x0f);
    try std.testing.expectEqual(@as(u8, 0xc3), first);
    try std.testing.expectEqual(@as(u8, 0x01), pn[0]);
    try std.testing.expectEqual(@as(u8, 0x02), pn[1]);
}
