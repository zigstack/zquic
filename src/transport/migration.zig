//! QUIC connection migration (RFC 9000 §9).
//!
//! Connection migration allows a QUIC endpoint to switch to a new network
//! path (e.g. when a mobile client changes from Wi-Fi to cellular).  The
//! key mechanisms are:
//!
//! 1. **PATH_CHALLENGE / PATH_RESPONSE** (RFC 9000 §9.3):
//!    The migrating endpoint sends a PATH_CHALLENGE with 8 random bytes.
//!    The peer echoes those bytes in a PATH_RESPONSE.
//!    Both frames were already defined in `src/frames/transport.zig`; this
//!    module provides the higher-level path validation state machine.
//!
//! 2. **Path probing** (RFC 9000 §9.1):
//!    A connection can probe a candidate path by sending non-probing frames
//!    (e.g., PADDING) on that path before migrating.
//!
//! 3. **Preferred Address** (RFC 9000 §9.6):
//!    The server can advertise a preferred address via transport parameters.
//!    This module stores and exposes that address.
//!
//! This module provides:
//!  - `PathState`: per-path validation state machine.
//!  - `MigrationManager`: tracks multiple candidate paths and the active path.
//!  - `PreferredAddress`: server-advertised preferred address.
//!  - `AntiAmpLimiter`: RFC 9000 §8.1 anti-amplification accounting.

const std = @import("std");
const compat = @import("../compat.zig");

// ---------------------------------------------------------------------------
// Path challenge data (8 random bytes, RFC 9000 §19.17)
// ---------------------------------------------------------------------------

pub const ChallengeData = [8]u8;

/// Generate cryptographically random PATH_CHALLENGE data.
pub fn randomChallenge() ChallengeData {
    var data: ChallengeData = undefined;
    compat.random.bytes(&data);
    return data;
}

// ---------------------------------------------------------------------------
// Anti-amplification (RFC 9000 §8.1)
// ---------------------------------------------------------------------------

pub const AntiAmpLimiter = struct {
    bytes_recv: u64 = 0,
    bytes_sent: u64 = 0,

    pub fn onRecv(self: *AntiAmpLimiter, n: usize) void {
        self.bytes_recv += @intCast(n);
    }

    pub fn onSent(self: *AntiAmpLimiter, n: usize) void {
        self.bytes_sent += @intCast(n);
    }

    pub fn canSend(self: *const AntiAmpLimiter, pkt_len: usize) bool {
        if (self.bytes_recv == 0) return false;
        return self.bytes_sent + @as(u64, @intCast(pkt_len)) <= self.bytes_recv * 3;
    }
};

// ---------------------------------------------------------------------------
// PathState
// ---------------------------------------------------------------------------

pub const PathStatus = enum {
    /// No validation has been initiated on this path.
    unknown,
    /// PATH_CHALLENGE sent; awaiting PATH_RESPONSE.
    probing,
    /// PATH_RESPONSE received and validated; path is usable.
    validated,
    /// Validation failed (timeout or wrong response data).
    failed,
};

/// State for a single candidate network path.
pub const PathState = struct {
    status: PathStatus = .unknown,
    /// The challenge data we sent (or are expecting to echo back).
    challenge: ChallengeData = .{0} ** 8,
    /// Number of validation attempts so far (retransmit limit: 3).
    attempts: u8 = 0,
    /// Timestamp of the last PATH_CHALLENGE send (ms).
    sent_at_ms: u64 = 0,

    /// Maximum validation attempts before marking path as failed.
    pub const max_attempts: u8 = 3;
    /// Validation timeout per attempt (ms).
    pub const timeout_ms: u64 = 1_000;

    /// Initiate path probing by recording the challenge and sending time.
    pub fn startProbing(self: *PathState, challenge: ChallengeData, now_ms: u64) void {
        self.challenge = challenge;
        self.status = .probing;
        self.attempts += 1;
        self.sent_at_ms = now_ms;
    }

    /// Process a received PATH_RESPONSE.  Returns true if the response
    /// matches our challenge and the path is now validated.
    pub fn handleResponse(self: *PathState, response: ChallengeData) bool {
        if (self.status != .probing) return false;
        if (!std.mem.eql(u8, &response, &self.challenge)) return false;
        self.status = .validated;
        return true;
    }

    /// Check for timeout; marks path as failed if max attempts exceeded.
    pub fn checkTimeout(self: *PathState, now_ms: u64) void {
        if (self.status != .probing) return;
        if (now_ms - self.sent_at_ms < timeout_ms) return;
        if (self.attempts >= max_attempts) {
            self.status = .failed;
        }
    }
};

// ---------------------------------------------------------------------------
// PreferredAddress
// ---------------------------------------------------------------------------

/// Server-preferred address from transport parameters (RFC 9000 §18.2).
pub const PreferredAddress = struct {
    /// IPv4 address (4 bytes), or all-zeros if not present.
    ipv4: [4]u8,
    ipv4_port: u16,
    /// IPv6 address (16 bytes), or all-zeros if not present.
    ipv6: [16]u8,
    ipv6_port: u16,
    /// New Connection ID the server will use on the new path.
    connection_id: [20]u8,
    connection_id_len: u8,
    /// Stateless reset token for the new connection ID.
    stateless_reset_token: [16]u8,

    pub fn hasIpv4(self: *const PreferredAddress) bool {
        return !std.mem.allEqual(u8, &self.ipv4, 0) or self.ipv4_port != 0;
    }

    pub fn hasIpv6(self: *const PreferredAddress) bool {
        return !std.mem.allEqual(u8, &self.ipv6, 0) or self.ipv6_port != 0;
    }
};

// ---------------------------------------------------------------------------
// MigrationManager
// ---------------------------------------------------------------------------

/// Maximum number of candidate paths tracked simultaneously.
pub const max_paths: usize = 4;

/// Manages path validation for connection migration.
pub const MigrationManager = struct {
    /// Candidate paths (index 0 is always the currently active path).
    paths: [max_paths]PathState = .{PathState{}} ** max_paths,
    /// Number of paths currently tracked.
    path_count: usize = 1,
    /// Index of the active (validated) path.
    active_path: usize = 0,
    /// Server-preferred address (null if not advertised).
    preferred_address: ?PreferredAddress = null,
    /// RFC 9000 §8.1 byte accounting for unvalidated paths.
    anti_amp: AntiAmpLimiter = .{},
    /// Latest PATH_CHALLENGE we sent while waiting for PATH_RESPONSE.
    pending_challenge: ?ChallengeData = null,

    /// Start probing a new candidate path.
    ///
    /// Returns the challenge data to send in a PATH_CHALLENGE frame, or
    /// null if the path table is full.
    pub fn probePath(self: *MigrationManager, now_ms: u64) ?ChallengeData {
        if (self.path_count >= max_paths) return null;
        const idx = self.path_count;
        self.path_count += 1;
        const challenge = randomChallenge();
        self.paths[idx].startProbing(challenge, now_ms);
        self.pending_challenge = challenge;
        return challenge;
    }

    /// Record a PATH_CHALLENGE for the current peer address (no new path slot).
    pub fn notePathChallenge(self: *MigrationManager, challenge: ChallengeData) void {
        self.pending_challenge = challenge;
    }

    /// Process a PATH_RESPONSE frame.
    ///
    /// If the response validates a candidate path, that path becomes active.
    /// Returns true if migration occurred.
    pub fn handlePathResponse(self: *MigrationManager, response: ChallengeData) bool {
        if (self.pending_challenge) |expected| {
            if (std.mem.eql(u8, &response, &expected)) {
                self.pending_challenge = null;
            }
        }
        for (0..self.path_count) |i| {
            if (i == self.active_path) continue;
            if (self.paths[i].handleResponse(response)) {
                self.active_path = i;
                return true;
            }
        }
        // Also let the active path handle it (peer re-validating us).
        return self.paths[self.active_path].handleResponse(response);
    }

    /// Tick the timeout check for all probing paths.
    pub fn tick(self: *MigrationManager, now_ms: u64) void {
        for (0..self.path_count) |i| {
            self.paths[i].checkTimeout(now_ms);
        }
    }

    /// Return the current active path status.
    pub fn activeStatus(self: *const MigrationManager) PathStatus {
        return self.paths[self.active_path].status;
    }

    /// Validate the current active path (called at startup, assuming the
    /// initial path is trusted).
    pub fn trustActivePath(self: *MigrationManager) void {
        self.paths[self.active_path].status = .validated;
    }

    pub fn setPreferredAddress(self: *MigrationManager, pa: PreferredAddress) void {
        self.preferred_address = pa;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "migration: PathState challenge/response" {
    const testing = std.testing;
    var path = PathState{};

    const challenge: ChallengeData = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    path.startProbing(challenge, 1000);
    try testing.expectEqual(PathStatus.probing, path.status);
    try testing.expectEqual(@as(u8, 1), path.attempts);

    // Wrong response should not validate.
    try testing.expect(!path.handleResponse(.{0} ** 8));
    try testing.expectEqual(PathStatus.probing, path.status);

    // Correct response validates.
    try testing.expect(path.handleResponse(challenge));
    try testing.expectEqual(PathStatus.validated, path.status);
}

test "migration: PathState timeout" {
    var path = PathState{};
    const challenge: ChallengeData = .{0xaa} ** 8;
    path.startProbing(challenge, 0);
    // Simulate max attempts expired.
    path.attempts = PathState.max_attempts;
    path.checkTimeout(PathState.timeout_ms + 1);
    try std.testing.expectEqual(PathStatus.failed, path.status);
}

test "migration: MigrationManager probe and migrate" {
    const testing = std.testing;
    var mgr = MigrationManager{};
    mgr.trustActivePath();

    // Probe a new path.
    const challenge = mgr.probePath(1000);
    try testing.expect(challenge != null);
    try testing.expectEqual(@as(usize, 2), mgr.path_count);

    // Handle a correct PATH_RESPONSE → migrate.
    const migrated = mgr.handlePathResponse(challenge.?);
    try testing.expect(migrated);
    try testing.expectEqual(@as(usize, 1), mgr.active_path);
}

test "migration: MigrationManager wrong response" {
    var mgr = MigrationManager{};
    mgr.trustActivePath();
    _ = mgr.probePath(1000);
    const wrong_resp: ChallengeData = .{0xff} ** 8;
    try std.testing.expect(!mgr.handlePathResponse(wrong_resp));
    try std.testing.expectEqual(@as(usize, 0), mgr.active_path);
}

test "migration: PreferredAddress helpers" {
    const testing = std.testing;
    var pa = PreferredAddress{
        .ipv4 = .{ 192, 168, 1, 1 },
        .ipv4_port = 4433,
        .ipv6 = .{0} ** 16,
        .ipv6_port = 0,
        .connection_id = .{0} ** 20,
        .connection_id_len = 0,
        .stateless_reset_token = .{0} ** 16,
    };
    try testing.expect(pa.hasIpv4());
    try std.testing.expect(!pa.hasIpv6());
}

test "migration: anti-amp 3x rule" {
    var amp = AntiAmpLimiter{};
    try std.testing.expect(!amp.canSend(100));
    amp.onRecv(100);
    try std.testing.expect(amp.canSend(300));
    try std.testing.expect(!amp.canSend(301));
}
