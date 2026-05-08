//! QUIC endpoint: UDP socket send/receive with QUIC packet dispatch.
//!
//! An Endpoint manages a UDP socket and maintains a table of active
//! connections keyed by destination connection ID. New incoming packets
//! are dispatched to the appropriate connection or trigger creation of a
//! new server-side connection.
//!
//! **Interop / demo only:** this type uses a small fixed-size connection
//! table (see `max_connections`) so the struct stays stack-friendly.
//! Production integrations should use the embedder API (`initFromSocket` /
//! `feedPacket` in `io.zig`) and manage connection tables on the heap with
//! whatever capacity and eviction policy they need.

const std = @import("std");
const compat = @import("../compat.zig");
const types = @import("../types.zig");
const connection = @import("connection.zig");
const packet = @import("../packet/packet.zig");
const header = @import("../packet/header.zig");
const varint = @import("../varint.zig");

pub const ConnectionId = types.ConnectionId;
pub const Connection = connection.Connection;

/// Maximum concurrent connections for this demo endpoint (fixed array → predictable
/// stack size). Not a protocol limit. Embedders using `io.zig` manage their own maps.
pub const max_connections = 8;

/// The result of processing a received datagram.
pub const RecvResult = enum {
    /// Dispatched to an existing connection.
    dispatched,
    /// Created a new server connection.
    new_connection,
    /// Packet was discarded (unknown CID, version mismatch, etc.).
    discarded,
};

/// A UDP endpoint that manages QUIC connections.
pub const Endpoint = struct {
    role: connection.Role,
    /// Active connections keyed by local DCID.
    conns: [max_connections]?Connection = [_]?Connection{null} ** max_connections,
    conn_count: usize = 0,

    /// Local UDP address.
    local_addr: compat.Address,

    pub fn init(role: connection.Role, addr: compat.Address) Endpoint {
        return .{ .role = role, .local_addr = addr };
    }

    /// Look up a connection by DCID.
    pub fn findConnection(self: *Endpoint, dcid: ConnectionId) ?*Connection {
        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                if (ConnectionId.eql(conn.local_cid, dcid)) return conn;
            }
        }
        return null;
    }

    /// Add a new connection to the endpoint.
    pub fn addConnection(self: *Endpoint, conn: Connection) error{TooManyConnections}!*Connection {
        for (&self.conns) |*slot| {
            if (slot.* == null) {
                slot.* = conn;
                self.conn_count += 1;
                return &(slot.*.?);
            }
        }
        return error.TooManyConnections;
    }

    /// Remove a connection from the endpoint.
    pub fn removeConnection(self: *Endpoint, dcid: ConnectionId) bool {
        for (&self.conns) |*slot| {
            if (slot.*) |conn| {
                if (ConnectionId.eql(conn.local_cid, dcid)) {
                    slot.* = null;
                    self.conn_count -= 1;
                    return true;
                }
            }
        }
        return false;
    }

    /// Process a received UDP datagram (buf contains the raw UDP payload).
    /// Returns how the packet was handled.
    pub fn receivePacket(self: *Endpoint, buf: []const u8) RecvResult {
        if (buf.len < 5) return .discarded;

        if (packet.isVersionNegotiation(buf)) {
            return .discarded; // handle version negotiation elsewhere
        }

        if (packet.isLongHeader(buf)) {
            const lh = header.parseLong(buf) catch return .discarded;
            const dcid = lh.header.dcid;

            if (self.findConnection(dcid)) |conn| {
                _ = conn;
                return .dispatched;
            }

            // Server: create new connection on Initial packet
            if (self.role == .server and lh.header.packet_type == .initial) {
                const local_cid = ConnectionId.random(compat.random, 8);
                var new_conn = Connection.init(.server, local_cid, dcid);
                new_conn.deriveInitialKeys(dcid);
                _ = self.addConnection(new_conn) catch return .discarded;
                return .new_connection;
            }
            return .discarded;
        } else {
            // Short header: look up by DCID
            // For short header, CID length is connection-specific; use a scan
            for (&self.conns) |*slot| {
                if (slot.*) |*conn| {
                    if (!conn.isConnected()) continue;
                    const cid_len = conn.local_cid.len;
                    if (buf.len < 1 + cid_len) continue;
                    const dcid_slice = buf[1 .. 1 + cid_len];
                    const candidate = ConnectionId.fromSlice(dcid_slice) catch continue;
                    if (ConnectionId.eql(conn.local_cid, candidate)) {
                        return .dispatched;
                    }
                }
            }
            return .discarded;
        }
    }
};

test "endpoint: add and find connection" {
    const testing = std.testing;

    const addr = try compat.Address.parseIp4("127.0.0.1", 4433);
    var ep = Endpoint.init(.server, addr);

    const lcid = try ConnectionId.fromSlice(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    const rcid = try ConnectionId.fromSlice(&[_]u8{ 0x05, 0x06 });
    const conn = Connection.init(.server, lcid, rcid);
    _ = try ep.addConnection(conn);

    const found = ep.findConnection(lcid);
    try testing.expect(found != null);
    try testing.expectEqual(@as(usize, 1), ep.conn_count);

    const removed = ep.removeConnection(lcid);
    try testing.expect(removed);
    try testing.expectEqual(@as(usize, 0), ep.conn_count);
}

test "endpoint: discard short unknown packet" {
    const addr = try compat.Address.parseIp4("127.0.0.1", 4433);
    var ep = Endpoint.init(.server, addr);

    // A short header packet with unknown CID
    const buf = [_]u8{ 0x40, 0xAA, 0xBB, 0xCC, 0xDD };
    const result = ep.receivePacket(&buf);
    try std.testing.expectEqual(RecvResult.discarded, result);
}

test "endpoint: version negotiation discarded" {
    const addr = try compat.Address.parseIp4("127.0.0.1", 4433);
    var ep = Endpoint.init(.server, addr);

    var vn_buf: [32]u8 = undefined;
    const dcid = try ConnectionId.fromSlice(&[_]u8{0xAA});
    const scid = try ConnectionId.fromSlice(&[_]u8{0xBB});
    const written = try packet.buildVersionNegotiation(&vn_buf, dcid, scid, &[_]u32{0x00000001});
    const result = ep.receivePacket(vn_buf[0..written]);
    try std.testing.expectEqual(RecvResult.discarded, result);
}
