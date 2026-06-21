//! NEW_TOKEN session tokens (RFC 9000 §8.1.3 / §19.7).
//!
//! Opaque address-validation tokens issued post-handshake, distinct from Retry
//! tokens (which embed the original DCID).  Format:
//!   [0]     magic 0xFF (Retry tokens use odcid_len ≤ 20, never 0xFF)
//!   [1..8]  mint timestamp, ms since epoch, big-endian i64
//!   [9..16] random nonce
//!   [17..48] HMAC-SHA256(secret, "zquic-nt" || timestamp || nonce)

const std = @import("std");
const compat = @import("../compat.zig");
const varint = @import("../varint.zig");

pub const magic: u8 = 0xff;
pub const token_len: usize = 49;
pub const ttl_ms: i64 = 24 * 60 * 60 * 1000;
const domain_label = "zquic-nt";

pub const ReplayLog = struct {
    const capacity: usize = 64;

    fingerprints: [capacity][32]u8 = undefined,
    count: usize = 0,

    fn fingerprint(token: []const u8) [32]u8 {
        var out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(token, &out, .{});
        return out;
    }

    pub fn contains(self: *const ReplayLog, token: []const u8) bool {
        const fp = fingerprint(token);
        const n = @min(self.count, capacity);
        for (self.fingerprints[0..n]) |entry| {
            if (std.crypto.timing_safe.eql([32]u8, entry, fp)) return true;
        }
        return false;
    }

    pub fn record(self: *ReplayLog, token: []const u8) void {
        const fp = fingerprint(token);
        if (self.count < capacity) {
            self.fingerprints[self.count] = fp;
            self.count += 1;
        } else {
            var i: usize = 1;
            while (i < capacity) : (i += 1) {
                self.fingerprints[i - 1] = self.fingerprints[i];
            }
            self.fingerprints[capacity - 1] = fp;
        }
    }
};

fn sessionHmac(key: *const [32]u8, ts_bytes: []const u8, nonce: []const u8) [32]u8 {
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(key);
    hmac.update(domain_label);
    hmac.update(ts_bytes);
    hmac.update(nonce);
    var mac: [32]u8 = undefined;
    hmac.final(&mac);
    return mac;
}

/// Mint a NEW_TOKEN payload into `out` (exactly `token_len` bytes).
pub fn mint(out: *[token_len]u8, secret: *const [32]u8) void {
    out[0] = magic;
    const ts_ms: i64 = @intCast(compat.milliTimestamp());
    std.mem.writeInt(i64, out[1..][0..8], ts_ms, .big);
    var nonce: [8]u8 = undefined;
    compat.random.bytes(&nonce);
    @memcpy(out[9..][0..8], &nonce);
    const mac = sessionHmac(secret, out[1..][0..8], &nonce);
    @memcpy(out[17..][0..32], &mac);
}

fn macValid(token: []const u8, secret: *const [32]u8) bool {
    if (token.len != token_len or token[0] != magic) return false;
    const ts_bytes = token[1..][0..8];
    const nonce = token[9..][0..8];
    const received_mac = token[17..][0..32];
    const expected = sessionHmac(secret, ts_bytes, nonce);
    var received: [32]u8 = undefined;
    @memcpy(&received, received_mac);
    return std.crypto.timing_safe.eql([32]u8, received, expected);
}

/// Validate token MAC, freshness, and replay log. Records on success.
pub fn verifyAndRecord(
    log: *ReplayLog,
    token: []const u8,
    secret: *const [32]u8,
    prev_secret: ?*const [32]u8,
) bool {
    if (token.len != token_len or token[0] != magic) return false;
    if (log.contains(token)) return false;

    var ok = macValid(token, secret);
    if (!ok) {
        if (prev_secret) |prev| ok = macValid(token, prev);
    }
    if (!ok) return false;

    const minted_ms = std.mem.readInt(i64, token[1..][0..8], .big);
    const now_ms = compat.milliTimestamp();
    const age_ms = now_ms - minted_ms;
    if (age_ms < 0 or age_ms > ttl_ms) return false;

    log.record(token);
    return true;
}

/// Serialize a NEW_TOKEN frame (type 0x07) into `buf`.
pub fn serializeFrame(token: []const u8, buf: []u8) !usize {
    var w = varint.Writer.init(buf);
    try w.writeVarint(0x07);
    try w.writeVarint(token.len);
    try w.writeBytes(token);
    return w.pos;
}

test "session_token: mint and verify" {
    const testing = std.testing;
    var secret: [32]u8 = undefined;
    @memset(&secret, 0x42);
    var token: [token_len]u8 = undefined;
    mint(&token, &secret);

    var log: ReplayLog = .{};
    try testing.expect(verifyAndRecord(&log, &token, &secret, null));
    try testing.expect(log.contains(&token));
    try testing.expect(!verifyAndRecord(&log, &token, &secret, null));
}

test "session_token: serialize frame" {
    const testing = std.testing;
    var secret: [32]u8 = undefined;
    @memset(&secret, 0x11);
    var token: [token_len]u8 = undefined;
    mint(&token, &secret);
    var buf: [64]u8 = undefined;
    const n = try serializeFrame(&token, &buf);
    try testing.expectEqual(@as(u8, 0x07), buf[0]);
    try testing.expect(n > token_len);
}
