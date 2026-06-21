//! RFC 9220 Extended CONNECT in HTTP/3 (SETTINGS + request/response helpers).

const std = @import("std");
const h3_frame = @import("frame.zig");
const h3_qpack = @import("qpack.zig");

/// RFC 9220 §3: SETTINGS_ENABLE_CONNECT_PROTOCOL.
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

pub const max_protocol_len: usize = 32;
pub const max_path_len: usize = 512;

pub const ConnectRequest = struct {
    path: []const u8,
    authority: []const u8,
    protocol: []const u8,
    scheme: []const u8 = "https",
};

/// Apply HTTP/3 SETTINGS that affect Extended CONNECT.
pub fn applySettings(settings: []const h3_frame.Setting, peer_connect_enabled: *bool) void {
    for (settings) |s| {
        if (s.id == SETTINGS_ENABLE_CONNECT_PROTOCOL and s.value == 1) {
            peer_connect_enabled.* = true;
        }
    }
}

/// Encode a CONNECT request HEADERS block into `out` (HTTP/3 frame not included).
pub fn encodeConnectRequest(
    req: ConnectRequest,
    out: []u8,
    table: ?*h3_qpack.DynamicTable,
) !usize {
    const headers = [_]h3_qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = req.protocol },
        .{ .name = ":scheme", .value = req.scheme },
        .{ .name = ":path", .value = req.path },
        .{ .name = ":authority", .value = req.authority },
    };
    return h3_qpack.encodeHeaders(&headers, out, .{ .table = table });
}

/// Encode a 200 response HEADERS block for an accepted Extended CONNECT.
pub fn encodeConnectResponse200(out: []u8, table: ?*h3_qpack.DynamicTable) !usize {
    const headers = [_]h3_qpack.Header{
        .{ .name = ":status", .value = "200" },
    };
    return h3_qpack.encodeHeaders(&headers, out, .{ .table = table });
}

/// Encode a 405 response when the peer did not enable Extended CONNECT.
pub fn encodeConnectResponse405(out: []u8, table: ?*h3_qpack.DynamicTable) !usize {
    const headers = [_]h3_qpack.Header{
        .{ .name = ":status", .value = "405" },
    };
    return h3_qpack.encodeHeaders(&headers, out, .{ .table = table });
}

test "connect: encode CONNECT request headers" {
    var block: [256]u8 = undefined;
    const n = try encodeConnectRequest(.{
        .path = "/wt",
        .authority = "example.com",
        .protocol = "webtransport-h3",
    }, &block, null);
    try std.testing.expect(n > 0);
}
