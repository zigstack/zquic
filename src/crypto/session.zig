//! QUIC session resumption: NewSessionTicket, PSK, and 0-RTT early data.
//!
//! TLS 1.3 session tickets (RFC 8446 §4.6.1) allow a client to resume a
//! previous connection without a full handshake (1-RTT resumption) or even
//! send application data before the handshake completes (0-RTT / early data).
//!
//! QUIC-specific details (RFC 9001 §4.6.1):
//! - The server encodes the resumption secret and QUIC transport parameters
//!   into an opaque ticket (NewSessionTicket TLS message).
//! - The client stores the ticket and uses it in the next connection via
//!   pre_shared_key and early_data TLS extensions.
//! - 0-RTT data is encrypted with the "early traffic secret" derived from
//!   the PSK.
//!
//! This module provides:
//! - `SessionTicket`: opaque ticket storage (serialise/deserialise).
//! - `TicketStore`: in-memory ring buffer of session tickets.
//! - `EarlyDataKeys`: 0-RTT key material derived from a PSK.
//! - `deriveEarlyKeys`: HKDF derivation for 0-RTT from a stored ticket.

// ── 0-RTT Anti-Replay (RFC 9001 §8.1 / RFC 8446 §8) ─────────────────────────
// zquic implements a 64-entry nonce cache keyed by the first 8 bytes of the
// PSK identity (ticket blob).  On a resumed connection the PSK identity is
// unique per ticket issuance; using its prefix as a nonce prevents replay of
// the same 0-RTT flight within the cache window.
// For read-only workloads (file serving) replays are idempotent, but the
// cache ensures correct RFC compliance for non-idempotent future extensions.

const std = @import("std");
const compat = @import("../compat.zig");
const crypto_keys = @import("keys.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum ticket lifetime in seconds (RFC 8446: max 604800 = 7 days).
pub const max_ticket_lifetime_s: u32 = 604_800;

/// Maximum number of tickets stored per connection.
pub const max_tickets: usize = 8;

/// Maximum ticket data length (opaque blob from server).
pub const max_ticket_len: usize = 1024;

// ---------------------------------------------------------------------------
// SessionTicket
// ---------------------------------------------------------------------------

/// An opaque TLS 1.3 session ticket received in a NewSessionTicket message.
pub const SessionTicket = struct {
    /// Ticket lifetime in seconds (from NewSessionTicket.ticket_lifetime).
    lifetime_s: u32,
    /// Anti-replay nonce (from NewSessionTicket.ticket_nonce).
    nonce: [32]u8,
    nonce_len: u8,
    /// Opaque ticket blob as sent by the server.
    ticket: [max_ticket_len]u8,
    ticket_len: usize,
    /// Resumption secret from which the PSK is derived.
    resumption_secret: [48]u8, // up to SHA-384 output
    resumption_secret_len: u8,
    /// Maximum early-data size advertised by the server (0 = disabled).
    max_early_data_size: u32,
    /// Timestamp (ms since epoch) when the ticket was received.
    received_at_ms: u64,

    /// Returns true if this ticket is still within its lifetime.
    pub fn isValid(self: *const SessionTicket, now_ms: u64) bool {
        const age_ms = now_ms -| self.received_at_ms;
        return age_ms < @as(u64, self.lifetime_s) * 1000;
    }

    /// Returns true if the server indicated 0-RTT is allowed.
    pub fn earlyDataAllowed(self: *const SessionTicket) bool {
        return self.max_early_data_size > 0;
    }

    /// Ticket age in milliseconds (obfuscated for the pre_shared_key extension).
    pub fn ageMs(self: *const SessionTicket, now_ms: u64) u32 {
        const age = now_ms -| self.received_at_ms;
        return @truncate(age);
    }

    /// Serialise to a compact wire format for persistent storage.
    ///
    /// Format:
    ///   u32 lifetime_s
    ///   u8  nonce_len
    ///   [nonce_len]u8
    ///   u16 ticket_len
    ///   [ticket_len]u8
    ///   u8  resumption_secret_len
    ///   [resumption_secret_len]u8
    ///   u32 max_early_data_size
    ///   u64 received_at_ms
    pub fn serialise(self: *const SessionTicket, buf: []u8) error{BufferTooSmall}!usize {
        const needed = 4 + 1 + self.nonce_len + 2 + self.ticket_len +
            1 + self.resumption_secret_len + 4 + 8;
        if (buf.len < needed) return error.BufferTooSmall;
        var pos: usize = 0;
        std.mem.writeInt(u32, buf[pos..][0..4], self.lifetime_s, .big);
        pos += 4;
        buf[pos] = self.nonce_len;
        pos += 1;
        @memcpy(buf[pos .. pos + self.nonce_len], self.nonce[0..self.nonce_len]);
        pos += self.nonce_len;
        std.mem.writeInt(u16, buf[pos..][0..2], @intCast(self.ticket_len), .big);
        pos += 2;
        @memcpy(buf[pos .. pos + self.ticket_len], self.ticket[0..self.ticket_len]);
        pos += self.ticket_len;
        buf[pos] = self.resumption_secret_len;
        pos += 1;
        @memcpy(buf[pos .. pos + self.resumption_secret_len], self.resumption_secret[0..self.resumption_secret_len]);
        pos += self.resumption_secret_len;
        std.mem.writeInt(u32, buf[pos..][0..4], self.max_early_data_size, .big);
        pos += 4;
        std.mem.writeInt(u64, buf[pos..][0..8], self.received_at_ms, .big);
        pos += 8;
        return pos;
    }

    /// Deserialise from the wire format produced by `serialise`.
    pub fn deserialise(buf: []const u8) error{ BufferTooShort, DataTooLong }!SessionTicket {
        if (buf.len < 4 + 1 + 2 + 1 + 4 + 8) return error.BufferTooShort;
        var pos: usize = 0;
        const lifetime_s = std.mem.readInt(u32, buf[pos..][0..4], .big);
        pos += 4;
        const nonce_len = buf[pos];
        pos += 1;
        if (pos + nonce_len > buf.len) return error.BufferTooShort;
        var nonce: [32]u8 = .{0} ** 32;
        if (nonce_len > 32) return error.DataTooLong;
        @memcpy(nonce[0..nonce_len], buf[pos .. pos + nonce_len]);
        pos += nonce_len;
        if (pos + 2 > buf.len) return error.BufferTooShort;
        const ticket_len = std.mem.readInt(u16, buf[pos..][0..2], .big);
        pos += 2;
        if (ticket_len > max_ticket_len) return error.DataTooLong;
        if (pos + ticket_len > buf.len) return error.BufferTooShort;
        var ticket: [max_ticket_len]u8 = .{0} ** max_ticket_len;
        @memcpy(ticket[0..ticket_len], buf[pos .. pos + ticket_len]);
        pos += ticket_len;
        if (pos + 1 > buf.len) return error.BufferTooShort;
        const rsl = buf[pos];
        pos += 1;
        if (rsl > 48) return error.DataTooLong;
        if (pos + rsl > buf.len) return error.BufferTooShort;
        var resumption_secret: [48]u8 = .{0} ** 48;
        @memcpy(resumption_secret[0..rsl], buf[pos .. pos + rsl]);
        pos += rsl;
        if (pos + 4 + 8 > buf.len) return error.BufferTooShort;
        const max_early = std.mem.readInt(u32, buf[pos..][0..4], .big);
        pos += 4;
        const received_at = std.mem.readInt(u64, buf[pos..][0..8], .big);
        return SessionTicket{
            .lifetime_s = lifetime_s,
            .nonce = nonce,
            .nonce_len = nonce_len,
            .ticket = ticket,
            .ticket_len = ticket_len,
            .resumption_secret = resumption_secret,
            .resumption_secret_len = rsl,
            .max_early_data_size = max_early,
            .received_at_ms = received_at,
        };
    }
};

// ---------------------------------------------------------------------------
// TicketStore
// ---------------------------------------------------------------------------

/// Ring-buffer store of session tickets (up to `max_tickets` per instance).
pub const TicketStore = struct {
    tickets: [max_tickets]?SessionTicket = .{null} ** max_tickets,
    head: usize = 0,
    count: usize = 0,

    /// Store a new ticket (overwrites oldest if full).
    pub fn store(self: *TicketStore, ticket: SessionTicket) void {
        self.tickets[self.head] = ticket;
        self.head = (self.head + 1) % max_tickets;
        if (self.count < max_tickets) self.count += 1;
    }

    /// Return the most recently stored valid ticket, or null.
    pub fn get(self: *const TicketStore, now_ms: u64) ?*const SessionTicket {
        // Scan from most recent backward.
        var i = max_tickets;
        while (i > 0) {
            i -= 1;
            const idx = (self.head + max_tickets - 1 - (max_tickets - 1 - i)) % max_tickets;
            if (self.tickets[idx]) |*t| {
                if (t.isValid(now_ms)) return t;
            }
        }
        return null;
    }

    pub fn isEmpty(self: *const TicketStore) bool {
        return self.count == 0;
    }
};

// ---------------------------------------------------------------------------
// Early Data (0-RTT) Key Derivation
// ---------------------------------------------------------------------------

/// 0-RTT key material derived from a PSK.
pub const EarlyDataKeys = struct {
    /// Write key (client → server for 0-RTT).
    key: [16]u8,
    /// IV for the AEAD.
    iv: [12]u8,
    /// Header protection key.
    hp: [16]u8,
};

/// Derive client_early_traffic_secret from PSK and ClientHello transcript hash.
///
/// RFC 8446 §7.1:
///   early_secret = HKDF-Extract(zeros_32, PSK)
///   client_early_traffic_secret =
///       HKDF-Expand-Label(early_secret, "c e traffic", ClientHello_hash, 32)
pub fn deriveEarlyTrafficSecret(psk: [32]u8, ch_hash: [32]u8) [32]u8 {
    const zeros: [32]u8 = .{0} ** 32;
    const early_secret = HkdfSha256.extract(&zeros, &psk);
    var cets: [32]u8 = undefined;
    crypto_keys.hkdfExpandLabel(&cets, &early_secret, "c e traffic", &ch_hash);
    return cets;
}

/// Derive QUIC 0-RTT keys from the client_early_traffic_secret.
pub fn deriveEarlyKeysFromSecret(early_traffic_secret: [32]u8) EarlyDataKeys {
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    var hp: [16]u8 = undefined;
    crypto_keys.hkdfExpandLabel(&key, &early_traffic_secret, "quic key", &.{});
    crypto_keys.hkdfExpandLabel(&iv, &early_traffic_secret, "quic iv", &.{});
    crypto_keys.hkdfExpandLabel(&hp, &early_traffic_secret, "quic hp", &.{});
    return .{ .key = key, .iv = iv, .hp = hp };
}

/// Derive 0-RTT (early data) AEAD keys from a session ticket's PSK.
/// Kept for backward-compatibility; callers that have the ClientHello
/// transcript hash should use deriveEarlyTrafficSecret + deriveEarlyKeysFromSecret.
pub fn deriveEarlyKeys(ticket: *const SessionTicket) EarlyDataKeys {
    // ticket.resumption_secret holds the PSK (= ticket blob sent by server).
    var psk: [32]u8 = .{0} ** 32;
    const plen = @min(ticket.resumption_secret_len, 32);
    @memcpy(psk[0..plen], ticket.resumption_secret[0..plen]);

    // Use an empty transcript hash as a conservative fallback.
    // Proper derivation requires the real ClientHello hash.
    const empty_hash = [32]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    const cets = deriveEarlyTrafficSecret(psk, empty_hash);
    return deriveEarlyKeysFromSecret(cets);
}

// ---------------------------------------------------------------------------
// 0-RTT Anti-Replay Nonce Cache
// ---------------------------------------------------------------------------

/// 64-entry ring-buffer nonce cache for 0-RTT anti-replay (RFC 9001 §8.1).
///
/// Key = first 8 bytes of the PSK identity (ticket blob).  Each ticket blob
/// is unique per issuance, so this prefix reliably distinguishes replays
/// within the cache window.
///
/// Usage:
///   if (!server.nonce_cache.checkAndInsert(key)) {
///       // Replay detected — do not activate early keys.
///   }
/// Maximum age (ms) for a nonce cache entry.  Entries older than this are
/// considered expired and silently evicted.  10 seconds covers typical
/// 0-RTT replay windows while limiting the cache's effective memory.
const NONCE_TTL_MS: i64 = 10_000;

pub const NonceCache = struct {
    const Entry = struct {
        key: [8]u8 = .{0} ** 8,
        inserted_ms: i64 = 0,
    };

    entries: [64]Entry = [_]Entry{.{}} ** 64,
    /// Number of valid entries (saturates at 64).
    count: usize = 0,
    /// Next write position in the ring.
    head: usize = 0,

    /// Check whether `key` has been seen before.
    /// Returns `true` (new) if the key is fresh and inserts it.
    /// Returns `false` (replay) if the key already exists and is not expired.
    pub fn checkAndInsert(self: *NonceCache, key: [8]u8) bool {
        const now_ms = compat.milliTimestamp();
        return self.checkAndInsertAt(key, now_ms);
    }

    /// Testable version that accepts an explicit timestamp.
    pub fn checkAndInsertAt(self: *NonceCache, key: [8]u8, now_ms: i64) bool {
        const n = @min(self.count, 64);
        for (0..n) |i| {
            // Skip expired entries.
            if (now_ms - self.entries[i].inserted_ms > NONCE_TTL_MS) continue;
            if (std.mem.eql(u8, &self.entries[i].key, &key)) return false; // replay
        }
        // Fresh key — insert at head.
        self.entries[self.head] = .{ .key = key, .inserted_ms = now_ms };
        self.head = (self.head + 1) % 64;
        if (self.count < 64) self.count += 1;
        return true;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "session: ticket serialise/deserialise round-trip" {
    const testing = std.testing;

    var ticket = SessionTicket{
        .lifetime_s = 3600,
        .nonce = .{0x01} ** 32,
        .nonce_len = 8,
        .ticket = .{0xab} ** max_ticket_len,
        .ticket_len = 32,
        .resumption_secret = .{0xcd} ** 48,
        .resumption_secret_len = 32,
        .max_early_data_size = 16384,
        .received_at_ms = 1_700_000_000_000,
    };

    var buf: [2048]u8 = undefined;
    const len = try ticket.serialise(&buf);
    const restored = try SessionTicket.deserialise(buf[0..len]);

    try testing.expectEqual(ticket.lifetime_s, restored.lifetime_s);
    try testing.expectEqual(ticket.nonce_len, restored.nonce_len);
    try testing.expectEqualSlices(u8, ticket.nonce[0..ticket.nonce_len], restored.nonce[0..restored.nonce_len]);
    try testing.expectEqual(ticket.ticket_len, restored.ticket_len);
    try testing.expectEqualSlices(u8, ticket.ticket[0..ticket.ticket_len], restored.ticket[0..restored.ticket_len]);
    try testing.expectEqual(ticket.max_early_data_size, restored.max_early_data_size);
    try testing.expectEqual(ticket.received_at_ms, restored.received_at_ms);
}

test "session: ticket validity" {
    const ticket = SessionTicket{
        .lifetime_s = 3600,
        .nonce = .{0} ** 32,
        .nonce_len = 0,
        .ticket = .{0} ** max_ticket_len,
        .ticket_len = 0,
        .resumption_secret = .{0} ** 48,
        .resumption_secret_len = 0,
        .max_early_data_size = 0,
        .received_at_ms = 1_000_000,
    };
    // Within lifetime (1 hour = 3 600 000 ms from received_at_ms).
    try std.testing.expect(ticket.isValid(1_000_000 + 3_599_999));
    // Expired.
    try std.testing.expect(!ticket.isValid(1_000_000 + 3_600_001));
}

test "session: ticket store ring buffer" {
    const testing = std.testing;
    var store = TicketStore{};
    try testing.expect(store.isEmpty());

    const base = SessionTicket{
        .lifetime_s = 3600,
        .nonce = .{0} ** 32,
        .nonce_len = 0,
        .ticket = .{0} ** max_ticket_len,
        .ticket_len = 0,
        .resumption_secret = .{0} ** 48,
        .resumption_secret_len = 0,
        .max_early_data_size = 1024,
        .received_at_ms = 0,
    };

    store.store(base);
    try testing.expect(!store.isEmpty());
    const t = store.get(1000);
    try testing.expect(t != null);
    try testing.expect(t.?.earlyDataAllowed());
}

test "session: early data key derivation" {
    const ticket = SessionTicket{
        .lifetime_s = 3600,
        .nonce = .{0} ** 32,
        .nonce_len = 0,
        .ticket = .{0} ** max_ticket_len,
        .ticket_len = 0,
        .resumption_secret = [_]u8{0x42} ** 48,
        .resumption_secret_len = 32,
        .max_early_data_size = 16384,
        .received_at_ms = 0,
    };
    const keys = deriveEarlyKeys(&ticket);
    // Keys should be non-zero (HKDF output is pseudorandom).
    try std.testing.expect(!std.mem.allEqual(u8, &keys.key, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &keys.iv, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &keys.hp, 0));
}

test "nonce_cache: detects replay" {
    const testing = std.testing;
    var cache = NonceCache{};
    const key: [8]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    try testing.expect(cache.checkAndInsert(key)); // first use: fresh
    try testing.expect(!cache.checkAndInsert(key)); // second use: replay
}

test "nonce_cache: ring eviction" {
    var cache = NonceCache{};
    // Fill all 64 slots.
    for (0..64) |i| {
        var k: [8]u8 = .{0} ** 8;
        k[0] = @intCast(i);
        try std.testing.expect(cache.checkAndInsert(k));
    }
    // A 65th distinct key should succeed (evicts oldest).
    const new_key: [8]u8 = .{0xff} ** 8;
    try std.testing.expect(cache.checkAndInsert(new_key));
    // The original key 0 may have been evicted; inserting it again is allowed
    // (cache ring wrapped around).  We just verify no panic occurs.
    const evicted: [8]u8 = .{0} ** 8;
    _ = cache.checkAndInsert(evicted);
}

test "nonce_cache: expired entries allow re-use" {
    const testing = std.testing;
    var cache = NonceCache{};
    const key: [8]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x01 };
    const t0: i64 = 1_000_000;
    try testing.expect(cache.checkAndInsertAt(key, t0)); // fresh
    try testing.expect(!cache.checkAndInsertAt(key, t0 + 5_000)); // still within TTL
    // After TTL expires, the same key should be accepted again.
    try testing.expect(cache.checkAndInsertAt(key, t0 + 10_001));
}
