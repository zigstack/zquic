//! QUIC connection state machine (RFC 9000).
//!
//! Manages the lifecycle of a single QUIC connection from Initial through
//! Handshake to Connected (1-RTT data transfer), and finally to Draining /
//! Closed states.
//!
//! State transitions:
//!
//!   Initial → Handshaking → Connected → DataTransfer → Draining → Closed

const std = @import("std");
const types = @import("../types.zig");
const varint = @import("../varint.zig");
const frames = @import("../frames/frame.zig");
const crypto_keys = @import("../crypto/keys.zig");
const quic_tls = @import("../crypto/quic_tls.zig");
const retry_mod = @import("../packet/retry.zig");
const version_neg = @import("../packet/version_negotiation.zig");

pub const ConnectionId = types.ConnectionId;
pub const TransportError = types.TransportError;

/// Connection state per RFC 9000 §4
pub const State = enum {
    /// Sending/receiving Initial packets; TLS handshake in progress.
    initial,
    /// Initial complete; sending/receiving Handshake packets.
    handshaking,
    /// Handshake complete; sending/receiving 1-RTT packets.
    connected,
    /// CONNECTION_CLOSE sent or received; waiting for draining period.
    draining,
    /// Connection fully terminated.
    closed,
};

/// Role of this endpoint.
pub const Role = enum { client, server };

/// Per-packet-number-space send state.
pub const PnSpaceState = struct {
    next_pn: u64 = 0,
    largest_acked: ?u64 = null,

    pub fn allocatePn(self: *PnSpaceState) u64 {
        const pn = self.next_pn;
        self.next_pn += 1;
        return pn;
    }
};

/// Sent-packet metadata for loss detection.
pub const SentPacket = struct {
    pn: u64,
    send_time_ms: u64,
    size: usize,
    ack_eliciting: bool,
    in_flight: bool,
};

/// UDP-layer counters (tx/rx datagrams and bytes).
pub const UdpStats = struct {
    datagrams_tx: u64 = 0,
    datagrams_rx: u64 = 0,
    bytes_tx: u64 = 0,
    bytes_rx: u64 = 0,
};

/// Per-frame-type counters (RFC 9000 §19).
pub const FrameStats = struct {
    ping_tx: u64 = 0,
    ping_rx: u64 = 0,
    ack_tx: u64 = 0,
    ack_rx: u64 = 0,
    reset_stream_tx: u64 = 0,
    reset_stream_rx: u64 = 0,
    stop_sending_tx: u64 = 0,
    stop_sending_rx: u64 = 0,
    crypto_tx: u64 = 0,
    crypto_rx: u64 = 0,
    new_token_tx: u64 = 0,
    new_token_rx: u64 = 0,
    stream_tx: u64 = 0,
    stream_rx: u64 = 0,
    max_data_tx: u64 = 0,
    max_data_rx: u64 = 0,
    max_stream_data_tx: u64 = 0,
    max_stream_data_rx: u64 = 0,
    max_streams_tx: u64 = 0,
    max_streams_rx: u64 = 0,
    data_blocked_tx: u64 = 0,
    data_blocked_rx: u64 = 0,
    stream_data_blocked_tx: u64 = 0,
    stream_data_blocked_rx: u64 = 0,
    streams_blocked_tx: u64 = 0,
    streams_blocked_rx: u64 = 0,
    new_connection_id_tx: u64 = 0,
    new_connection_id_rx: u64 = 0,
    retire_connection_id_tx: u64 = 0,
    retire_connection_id_rx: u64 = 0,
    path_challenge_tx: u64 = 0,
    path_challenge_rx: u64 = 0,
    path_response_tx: u64 = 0,
    path_response_rx: u64 = 0,
    connection_close_tx: u64 = 0,
    connection_close_rx: u64 = 0,
    handshake_done_tx: u64 = 0,
    handshake_done_rx: u64 = 0,
};

/// Path / loss / congestion snapshot fields (mirrors quinn `PathStats`).
pub const PathStats = struct {
    srtt_ms: f64 = 0,
    min_rtt_ms: u64 = 0,
    rttvar_ms: f64 = 0,
    cwnd: u64 = 0,
    bytes_in_flight: u64 = 0,
    congestion_events: u64 = 0,
    lost_packets: u64 = 0,
    lost_bytes: u64 = 0,
    pto_count: u64 = 0,
    current_mtu: u16 = 0,
    ecn_ect0_recv: u64 = 0,
    ecn_ect1_recv: u64 = 0,
    ecn_ce_recv: u64 = 0,
    plpmtud_probes_sent: u64 = 0,
    plpmtud_probes_acked: u64 = 0,
    black_hole_detections: u64 = 0,
};

/// Cumulative counters maintained on the live connection.
pub const StatsAccumulator = struct {
    udp: UdpStats = .{},
    frames: FrameStats = .{},
    lost_packets: u64 = 0,
    lost_bytes: u64 = 0,
    plpmtud_probes_sent: u64 = 0,
    plpmtud_probes_acked: u64 = 0,
    black_hole_detections: u64 = 0,
};

/// Connection-level statistics snapshot.
pub const Stats = struct {
    udp: UdpStats = .{},
    frames: FrameStats = .{},
    path: PathStats = .{},
    /// Legacy top-level aliases (datagram / byte totals).
    packets_sent: u64 = 0,
    packets_recv: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_recv: u64 = 0,
    handshake_rtt_ms: ?u64 = null,
};

/// ACK manager: tracks received packets that need to be acknowledged.
pub const AckManager = struct {
    const max_ranges = 32;

    /// Largest packet number seen so far.
    largest_recv: u64 = 0,
    /// Number of filled ranges.
    range_count: usize = 0,
    /// Received packet ranges (not yet sent in ACK frame).
    ranges: [max_ranges][2]u64 = undefined,
    /// True when an ACK needs to be sent.
    needs_ack: bool = false,

    /// Record a received packet number.
    pub fn observe(self: *AckManager, pn: u64) void {
        if (pn > self.largest_recv) self.largest_recv = pn;
        self.needs_ack = true;
        // Simple tracking: merge into the last range if contiguous.
        if (self.range_count == 0) {
            self.ranges[0] = .{ pn, pn };
            self.range_count = 1;
            return;
        }
        const last = &self.ranges[self.range_count - 1];
        if (pn == last[0] - 1) {
            last[0] = pn;
        } else if (pn == last[1] + 1) {
            last[1] = pn;
        } else if (self.range_count < max_ranges) {
            self.ranges[self.range_count] = .{ pn, pn };
            self.range_count += 1;
        }
    }

    /// Build an ACK frame and clear the pending state.
    pub fn buildAck(self: *AckManager) @import("../frames/ack.zig").AckFrame {
        const ack_frame = @import("../frames/ack.zig");
        var f = ack_frame.AckFrame{
            .largest_acknowledged = self.largest_recv,
            .ack_delay = 0,
            .ranges = undefined,
            .range_count = 0,
            .ecn = null,
        };
        // Build ranges (largest first)
        var i = self.range_count;
        while (i > 0 and f.range_count < ack_frame.max_ack_ranges) {
            i -= 1;
            f.ranges[f.range_count] = .{
                .smallest = self.ranges[i][0],
                .largest = self.ranges[i][1],
            };
            f.range_count += 1;
        }
        self.needs_ack = false;
        return f;
    }
};

/// A QUIC connection.
pub const Connection = struct {
    role: Role,
    state: State = .initial,

    /// Local and remote connection IDs.
    local_cid: ConnectionId,
    remote_cid: ConnectionId,

    /// Per-packet-number-space state.
    initial_pn: PnSpaceState = .{},
    handshake_pn: PnSpaceState = .{},
    app_pn: PnSpaceState = .{},

    /// ACK managers per packet number space.
    initial_ack: AckManager = .{},
    handshake_ack: AckManager = .{},
    app_ack: AckManager = .{},

    /// Crypto streams per encryption level.
    initial_crypto: quic_tls.CryptoStream = .{},
    handshake_crypto: quic_tls.CryptoStream = .{},
    app_crypto: quic_tls.CryptoStream = .{},

    /// Initial packet crypto keys (derived from DCID).
    initial_keys: ?crypto_keys.InitialSecrets = null,

    /// Connection-level flow control limit (bytes we can send).
    max_data: u64 = 0,
    /// Bytes sent so far (for flow control).
    data_sent: u64 = 0,

    /// Close error, if any.
    close_error: ?TransportError = null,

    /// Retry token received from server (client-side only).
    /// Used in the client's retry-response Initial packet.
    /// One opaque token; 256 is a conservative max byte length (RFC 9000 does not cap it).
    retry_token: ?[256]u8 = null,
    retry_token_len: usize = 0,

    /// Original Destination Connection ID (ODCID) – set on client when
    /// a Retry is received so the client can verify the Retry integrity tag.
    original_dcid: ?ConnectionId = null,

    /// Statistics.
    stats: Stats = .{},

    pub fn init(role: Role, local_cid: ConnectionId, remote_cid: ConnectionId) Connection {
        return .{
            .role = role,
            .local_cid = local_cid,
            .remote_cid = remote_cid,
        };
    }

    /// Derive Initial packet keys using the destination CID.
    pub fn deriveInitialKeys(self: *Connection, dcid: ConnectionId) void {
        self.initial_keys = crypto_keys.InitialSecrets.derive(dcid.slice());
    }

    /// Returns true once the TLS handshake is complete (state = connected).
    pub fn isConnected(self: *const Connection) bool {
        return self.state == .connected;
    }

    /// Returns the appropriate packet number space for the current state.
    pub fn currentPnSpace(self: *Connection) *PnSpaceState {
        return switch (self.state) {
            .initial => &self.initial_pn,
            .handshaking => &self.handshake_pn,
            .connected, .draining, .closed => &self.app_pn,
        };
    }

    /// Transition to a new state (validates transitions).
    pub fn transition(self: *Connection, new_state: State) error{InvalidTransition}!void {
        const valid = switch (self.state) {
            .initial => new_state == .handshaking or new_state == .draining or new_state == .closed,
            .handshaking => new_state == .connected or new_state == .draining or new_state == .closed,
            .connected => new_state == .draining or new_state == .closed,
            .draining => new_state == .closed,
            .closed => false,
        };
        if (!valid) return error.InvalidTransition;
        self.state = new_state;
    }

    /// Close the connection with a transport error.
    pub fn closeWithError(self: *Connection, err: TransportError) void {
        self.close_error = err;
        self.state = .draining;
    }

    /// Handle a received Retry packet (client-side only).
    ///
    /// Verifies the Retry integrity tag using the ODCID. On success the
    /// client must restart the handshake:
    /// - Replace the remote CID with the SCID from the Retry packet.
    /// - Store the retry token for inclusion in the next Initial packet.
    /// - Reset packet number space back to 0.
    /// - Re-derive initial keys with the new remote CID.
    ///
    /// Returns an error if:
    /// - Called on a server-role connection
    /// - The integrity tag is invalid
    /// - A Retry was already processed for this connection
    pub fn handleRetry(
        self: *Connection,
        scid: []const u8,
        token: []const u8,
        retry_packet_with_tag: []const u8,
    ) error{ WrongRole, InvalidRetryTag, AlreadyRetried, TooLong }!void {
        if (self.role != .client) return error.WrongRole;
        if (self.original_dcid != null) return error.AlreadyRetried;

        // Save ODCID before overwriting remote_cid.
        self.original_dcid = self.remote_cid;

        // Verify integrity tag using ODCID.
        const odcid_slice = self.original_dcid.?.slice();
        if (!retry_mod.verifyIntegrityTag(odcid_slice, retry_packet_with_tag)) {
            self.original_dcid = null; // Roll back.
            return error.InvalidRetryTag;
        }

        // Store retry token.
        if (token.len > self.retry_token.?.len) return error.TooLong;
        self.retry_token = [_]u8{0} ** 256;
        @memcpy(self.retry_token.?[0..token.len], token);
        self.retry_token_len = token.len;

        // Update remote CID and re-derive Initial keys with the new SCID.
        self.remote_cid = try ConnectionId.fromSlice(scid);
        self.deriveInitialKeys(self.remote_cid);

        // Reset Initial packet number space.
        self.initial_pn = .{};
        self.initial_ack = .{};
    }

    /// Handle a received Version Negotiation packet (client-side only).
    ///
    /// Parses the server's supported versions and fails if QUIC v1 is not listed.
    /// The full client stack also performs compatible version negotiation when
    /// upgrading to QUIC v2 (see `io.zig`: server Initial handling and v2 key promotion).
    ///
    /// Returns error.WrongRole for server connections.
    /// Returns error.NoCommonVersion if QUIC v1 is absent from the list.
    pub fn handleVersionNegotiation(
        self: *Connection,
        vn_packet: []const u8,
    ) error{ WrongRole, NoCommonVersion, ParseError }!void {
        if (self.role != .client) return error.WrongRole;
        const pkt = version_neg.parse(vn_packet) catch return error.ParseError;
        var it = pkt.versions();
        while (it.next()) |v| {
            if (v == version_neg.QUIC_V1) {
                return;
            }
        }
        // No common version — close the connection.
        self.closeWithError(.protocol_violation);
        return error.NoCommonVersion;
    }
};

test "connection: state machine transitions" {
    const testing = std.testing;

    const dcid = try ConnectionId.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    const scid = try ConnectionId.fromSlice(&[_]u8{ 0x04, 0x05 });
    var conn = Connection.init(.client, scid, dcid);

    try testing.expectEqual(State.initial, conn.state);

    try conn.transition(.handshaking);
    try testing.expectEqual(State.handshaking, conn.state);

    try conn.transition(.connected);
    try testing.expectEqual(State.connected, conn.state);

    try conn.transition(.draining);
    try testing.expectEqual(State.draining, conn.state);

    try conn.transition(.closed);
    try testing.expectEqual(State.closed, conn.state);
}

test "connection: invalid transition" {
    const dcid = try ConnectionId.fromSlice(&[_]u8{0x01});
    const scid = try ConnectionId.fromSlice(&[_]u8{0x02});
    var conn = Connection.init(.server, scid, dcid);

    try std.testing.expectError(error.InvalidTransition, conn.transition(.connected));
}

test "connection: initial key derivation" {
    const testing = std.testing;

    const dcid = try ConnectionId.fromSlice("\x83\x94\xc8\xf0\x3e\x51\x57\x08");
    const scid = try ConnectionId.fromSlice(&[_]u8{0x00});
    var conn = Connection.init(.client, scid, dcid);
    conn.deriveInitialKeys(dcid);

    try testing.expect(conn.initial_keys != null);
    const expected_key = "\x1f\x36\x96\x13\xdd\x76\xd5\x46\x77\x30\xef\xcb\xe3\xb1\xa2\x2d";
    try testing.expectEqualSlices(u8, expected_key, &conn.initial_keys.?.client.key);
}

test "connection: handle retry packet" {
    const testing = std.testing;

    const dcid_bytes = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const dcid = try ConnectionId.fromSlice(&dcid_bytes);
    const scid_bytes = [_]u8{ 0x01, 0x02 };
    const scid = try ConnectionId.fromSlice(&scid_bytes);
    var conn = Connection.init(.client, scid, dcid);
    conn.deriveInitialKeys(dcid);
    conn.retry_token = [_]u8{0} ** 256;

    const new_scid = [_]u8{ 0xaa, 0xbb };
    const token = "retry-token";

    // Build a valid Retry packet.
    var retry_buf: [256]u8 = undefined;
    const retry_written = try retry_mod.buildRetryPacket(
        &retry_buf,
        0x00000001,
        &[_]u8{ 0x10, 0x11 }, // dcid echoed to client
        &new_scid,
        token,
        &dcid_bytes, // odcid
    );

    try conn.handleRetry(&new_scid, token, retry_buf[0..retry_written]);

    // After Retry, remote_cid should be updated.
    try testing.expectEqualSlices(u8, &new_scid, conn.remote_cid.slice());
    // ODCID should be stored.
    try testing.expectEqualSlices(u8, &dcid_bytes, conn.original_dcid.?.slice());
    // Token stored.
    try testing.expectEqualSlices(u8, token, conn.retry_token.?[0..conn.retry_token_len]);
    // Initial PN reset.
    try testing.expectEqual(@as(u64, 0), conn.initial_pn.next_pn);
}

test "connection: handle retry with bad tag" {
    const dcid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const dcid = try ConnectionId.fromSlice(&dcid_bytes);
    const scid = try ConnectionId.fromSlice(&[_]u8{0x10});
    var conn = Connection.init(.client, scid, dcid);
    conn.retry_token = [_]u8{0} ** 256;

    // Build a Retry packet with a wrong ODCID so the tag check fails.
    const wrong_odcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var retry_buf: [128]u8 = undefined;
    const retry_written = try retry_mod.buildRetryPacket(
        &retry_buf,
        0x00000001,
        &[_]u8{0x05},
        &[_]u8{0x06},
        "token",
        &wrong_odcid, // deliberately wrong
    );

    const result = conn.handleRetry(&[_]u8{0x06}, "token", retry_buf[0..retry_written]);
    try std.testing.expectError(error.InvalidRetryTag, result);
}

test "connection: version negotiation common version" {
    const testing = std.testing;
    const dcid = try ConnectionId.fromSlice(&[_]u8{0x01});
    const scid = try ConnectionId.fromSlice(&[_]u8{0x02});
    var conn = Connection.init(.client, scid, dcid);

    var buf: [32]u8 = undefined;
    const written = try version_neg.build(&buf, &[_]u8{0x01}, &[_]u8{0x02}, &[_]u32{ version_neg.QUIC_V1, 0xfaceb002 });
    try conn.handleVersionNegotiation(buf[0..written]);
    // Still initial state – a common version was found.
    try testing.expectEqual(State.initial, conn.state);
}

test "connection: version negotiation no common version" {
    const dcid = try ConnectionId.fromSlice(&[_]u8{0x01});
    const scid = try ConnectionId.fromSlice(&[_]u8{0x02});
    var conn = Connection.init(.client, scid, dcid);

    var buf: [32]u8 = undefined;
    const written = try version_neg.build(&buf, &[_]u8{0x01}, &[_]u8{0x02}, &[_]u32{0xfaceb002});
    const result = conn.handleVersionNegotiation(buf[0..written]);
    try std.testing.expectError(error.NoCommonVersion, result);
    // Connection should be draining.
    try std.testing.expectEqual(State.draining, conn.state);
}

test "ack_manager: single packet observation" {
    const testing = std.testing;
    var mgr = AckManager{};

    mgr.observe(5);
    mgr.observe(6);
    mgr.observe(7);
    try testing.expect(mgr.needs_ack);
    try testing.expectEqual(@as(u64, 7), mgr.largest_recv);

    const ack = mgr.buildAck();
    try testing.expect(ack.acknowledges(6));
    try testing.expect(!mgr.needs_ack);
}
