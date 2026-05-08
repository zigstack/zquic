//! QLOG writer for QUIC event logging (IETF QLOG draft-07 / version 0.3).
//!
//! Each QUIC connection produces one `.sqlog` file in the configured output
//! directory.  The file uses the NDJSON streaming format: the first line is a
//! JSON header describing the trace, and each subsequent line is one event.
//!
//! File naming: `<ODCID_hex>.sqlog` where ODCID is the original destination
//! connection ID from the client's first Initial packet (the server's view) or
//! the DCID the client chose for its first packet (the client's view).
//!
//! Format (per event line):
//!   {"time":<ms_relative>,"name":"<category>:<event>","data":{...}}
//!
//! Reference: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema
//!            https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-quic-events

const std = @import("std");
const compat = @import("../compat.zig");

// ---------------------------------------------------------------------------
// PacketType enum — used in packet_sent / packet_received events
// ---------------------------------------------------------------------------

pub const PacketType = enum {
    initial,
    handshake,
    zero_rtt,
    one_rtt,
    retry,
    version_negotiation,
    unknown,

    pub fn str(self: PacketType) []const u8 {
        return switch (self) {
            .initial => "initial",
            .handshake => "handshake",
            .zero_rtt => "0RTT",
            .one_rtt => "1RTT",
            .retry => "retry",
            .version_negotiation => "version_negotiation",
            .unknown => "unknown",
        };
    }
};

// ---------------------------------------------------------------------------
// QlogWriter
// ---------------------------------------------------------------------------

/// Writes QLOG events for a single QUIC connection to a `.sqlog` file.
///
/// All methods are no-ops when the writer is disabled (`file == null`), so
/// callers need no null-checks at the call site.
///
/// Thread safety: not thread-safe; use one writer per connection.
pub const Writer = struct {
    file: ?compat.fs.File = null,
    /// Unix timestamp (ms) when the connection started.  All event `time`
    /// fields are relative to this value.
    reference_ms: i64 = 0,

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Open a `.sqlog` file for `odcid` in `qlog_dir` and write the trace
    /// header line.  `vantage` is "server" or "client".
    /// Does nothing and returns a disabled writer on any error.
    pub fn open(
        qlog_dir: []const u8,
        odcid_bytes: []const u8,
        vantage: []const u8,
    ) Writer {
        // Build file path: "<qlog_dir>/<odcid_hex>.sqlog"
        var path_buf: [512]u8 = undefined;
        const hex = hexEncode(odcid_bytes);
        const path = std.fmt.bufPrint(&path_buf, "{s}/{s}.sqlog", .{ qlog_dir, hex.slice() }) catch return .{};

        compat.fs.makeDirAbsolute(qlog_dir) catch {};
        const file = compat.fs.createFileAbsolute(path, .{}) catch return .{};

        const now_ms = compat.milliTimestamp();

        // Write NDJSON trace header.
        var w: Writer = .{ .file = file, .reference_ms = now_ms };
        w.writeFmt(
            "{{\"qlog_version\":\"0.3\",\"qlog_format\":\"JSON-SEQ\"," ++
                "\"title\":\"zquic\",\"description\":\"zquic QUIC connection\"," ++
                "\"traces\":[{{\"vantage_point\":{{\"name\":\"{s}\",\"type\":\"{s}\"}}," ++
                "\"common_fields\":{{\"group_id\":\"{s}\",\"ODCID\":\"{s}\"," ++
                "\"reference_time\":{},\"time_format\":\"relative\"," ++
                "\"protocol_type\":[\"QUIC\"]}}}}]}}\n",
            .{ vantage, vantage, hex.slice(), hex.slice(), now_ms },
        );
        return w;
    }

    /// Flush and close the underlying file.
    pub fn close(self: *Writer) void {
        if (self.file) |f| {
            f.close();
            self.file = null;
        }
    }

    // -----------------------------------------------------------------------
    // Connection events
    // -----------------------------------------------------------------------

    /// Emit `transport:connection_started`.
    pub fn connectionStarted(
        self: *Writer,
        src_ip: []const u8,
        src_port: u16,
        dst_ip: []const u8,
        dst_port: u16,
        quic_version: u32,
    ) void {
        self.writeEvent(
            "transport:connection_started",
            "{{\"src_ip\":\"{s}\",\"src_port\":{},\"dst_ip\":\"{s}\",\"dst_port\":{}," ++
                "\"quic_version\":\"0x{x:0>8}\"}}",
            .{ src_ip, src_port, dst_ip, dst_port, quic_version },
        );
    }

    /// Emit `transport:connection_closed`.  `trigger` is a short reason string
    /// such as `"clean_shutdown"`, `"timeout"`, or `"error"`.
    pub fn connectionClosed(self: *Writer, trigger: []const u8) void {
        self.writeEvent(
            "transport:connection_closed",
            "{{\"owner\":\"local\",\"trigger\":\"{s}\"}}",
            .{trigger},
        );
    }

    // -----------------------------------------------------------------------
    // Packet events
    // -----------------------------------------------------------------------

    /// Emit `transport:packet_sent`.
    pub fn packetSent(
        self: *Writer,
        pkt_type: PacketType,
        packet_number: u64,
        payload_len: usize,
    ) void {
        self.writeEvent(
            "transport:packet_sent",
            "{{\"packet_type\":\"{s}\",\"header\":{{\"packet_number\":{}}}," ++
                "\"raw\":{{\"length\":{}}}}}",
            .{ pkt_type.str(), packet_number, payload_len },
        );
    }

    /// Emit `transport:packet_received`.
    pub fn packetReceived(
        self: *Writer,
        pkt_type: PacketType,
        packet_number: u64,
        payload_len: usize,
    ) void {
        self.writeEvent(
            "transport:packet_received",
            "{{\"packet_type\":\"{s}\",\"header\":{{\"packet_number\":{}}}," ++
                "\"raw\":{{\"length\":{}}}}}",
            .{ pkt_type.str(), packet_number, payload_len },
        );
    }

    /// Emit `transport:packet_dropped`.  `trigger` e.g. `"decryption_failure"`.
    pub fn packetDropped(self: *Writer, trigger: []const u8) void {
        self.writeEvent(
            "transport:packet_dropped",
            "{{\"trigger\":\"{s}\"}}",
            .{trigger},
        );
    }

    // -----------------------------------------------------------------------
    // Security / key events
    // -----------------------------------------------------------------------

    /// Emit `security:key_updated`.  `key_type` e.g. `"client_1rtt_secret"`.
    pub fn keyUpdated(self: *Writer, key_type: []const u8, trigger: []const u8) void {
        self.writeEvent(
            "security:key_updated",
            "{{\"key_type\":\"{s}\",\"trigger\":\"{s}\"}}",
            .{ key_type, trigger },
        );
    }

    // -----------------------------------------------------------------------
    // Recovery / congestion events
    // -----------------------------------------------------------------------

    /// Emit `recovery:metrics_updated` with current RTT and congestion state.
    pub fn metricsUpdated(
        self: *Writer,
        min_rtt_ms: f64,
        smoothed_rtt_ms: f64,
        congestion_window: u64,
        bytes_in_flight: u64,
    ) void {
        self.writeEvent(
            "recovery:metrics_updated",
            "{{\"min_rtt\":{d:.3},\"smoothed_rtt\":{d:.3}," ++
                "\"congestion_window\":{},\"bytes_in_flight\":{}}}",
            .{ min_rtt_ms, smoothed_rtt_ms, congestion_window, bytes_in_flight },
        );
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Write one event line: {"time":<ms>,"name":"<name>","data":<data_json>}\n
    fn writeEvent(
        self: *Writer,
        comptime name: []const u8,
        comptime data_fmt: []const u8,
        data_args: anytype,
    ) void {
        if (self.file == null) return;
        const now_ms = compat.milliTimestamp();
        const rel: f64 = @floatFromInt(now_ms - self.reference_ms);
        // Write time+name prefix.
        self.writeFmt("{{\"time\":{d:.3},\"name\":\"{s}\",\"data\":", .{ rel, name });
        // Write data object.
        self.writeFmt(data_fmt, data_args);
        // Close the event object.
        self.writeFmt("}}\n", .{});
    }

    /// Write formatted text directly to the file.  Silently swallows errors.
    fn writeFmt(self: *Writer, comptime fmt: []const u8, args: anytype) void {
        if (self.file) |f| {
            var buf: [2048]u8 = undefined;
            const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
            f.writeAll(s) catch {};
        }
    }
};

// ---------------------------------------------------------------------------
// Hex encoding helper (no allocator needed)
// ---------------------------------------------------------------------------

const MAX_HEX_LEN = 40; // 20-byte DCID → 40 hex chars

const HexBuf = struct {
    buf: [MAX_HEX_LEN]u8 = [_]u8{0} ** MAX_HEX_LEN,
    len: usize = 0,

    pub fn slice(self: *const HexBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

fn hexEncode(bytes: []const u8) HexBuf {
    var h = HexBuf{};
    const hex_digits = "0123456789abcdef";
    var i: usize = 0;
    for (bytes) |b| {
        if (i + 2 > MAX_HEX_LEN) break;
        h.buf[i] = hex_digits[b >> 4];
        h.buf[i + 1] = hex_digits[b & 0x0F];
        i += 2;
    }
    h.len = i;
    return h;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "qlog writer: hexEncode" {
    const testing = std.testing;
    const h = hexEncode(&[_]u8{ 0x83, 0x94, 0xc8, 0xf0 });
    try testing.expectEqualSlices(u8, "8394c8f0", h.slice());
}

test "qlog writer: hexEncode empty" {
    const h = hexEncode(&[_]u8{});
    try std.testing.expectEqual(@as(usize, 0), h.len);
}

test "qlog writer: disabled writer is a no-op" {
    // A writer with file=null must never crash.
    var w = Writer{};
    w.connectionStarted("127.0.0.1", 4433, "127.0.0.1", 443, 0x00000001);
    w.packetSent(.one_rtt, 42, 1200);
    w.packetReceived(.initial, 0, 1252);
    w.packetDropped("decryption_failure");
    w.keyUpdated("client_1rtt_secret", "tls");
    w.metricsUpdated(5.0, 12.5, 14720, 4800);
    w.connectionClosed("clean_shutdown");
    w.close(); // must not crash
}

test "qlog writer: write to tmp file and verify content" {
    const testing = std.testing;

    // Use a fixed-path tmp directory.  The old `std.testing.tmpDir().dir.realpath`
    // helper relied on `std.fs` / `std.testing` APIs that were reworked into
    // `std.Io.Dir` in zig 0.16; while the rest of the test suite still passes
    // by going through the compat shim, the testing helpers themselves are
    // not yet ported — so use a deterministic path here.
    const tmp_path = "/tmp/zquic-qlog-test";
    compat.fs.makeDirAbsolute(tmp_path) catch {};

    const odcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var w = Writer.open(tmp_path, &odcid, "server");
    defer w.close();

    try testing.expect(w.file != null);

    w.connectionStarted("10.0.0.1", 443, "10.0.0.2", 12345, 0x00000001);
    w.packetSent(.initial, 0, 1252);
    w.packetReceived(.initial, 0, 1200);
    w.packetSent(.one_rtt, 1, 100);
    w.keyUpdated("server_1rtt_secret", "tls");
    w.connectionClosed("clean_shutdown");
    w.close();

    // Verify the file was created and contains recognisable content.
    var sqlog_path_buf: [512]u8 = undefined;
    const sqlog_path = try std.fmt.bufPrint(&sqlog_path_buf, "{s}/01020304.sqlog", .{tmp_path});
    const content = try compat.fs.openFileAbsolute(sqlog_path, .{});
    defer content.close();
    var read_buf: [4096]u8 = undefined;
    const n = try content.readAll(&read_buf);
    const text = read_buf[0..n];

    // Header line.
    try testing.expect(std.mem.indexOf(u8, text, "qlog_version") != null);
    try testing.expect(std.mem.indexOf(u8, text, "01020304") != null);
    try testing.expect(std.mem.indexOf(u8, text, "server") != null);

    // Events.
    try testing.expect(std.mem.indexOf(u8, text, "transport:connection_started") != null);
    try testing.expect(std.mem.indexOf(u8, text, "transport:packet_sent") != null);
    try testing.expect(std.mem.indexOf(u8, text, "transport:packet_received") != null);
    try testing.expect(std.mem.indexOf(u8, text, "security:key_updated") != null);
    try testing.expect(std.mem.indexOf(u8, text, "transport:connection_closed") != null);
    try testing.expect(std.mem.indexOf(u8, text, "initial") != null);
    try testing.expect(std.mem.indexOf(u8, text, "1RTT") != null);
}
