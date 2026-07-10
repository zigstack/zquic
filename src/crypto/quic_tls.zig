//! QUIC-TLS adapter (RFC 9001).
//!
//! QUIC replaces the TLS record layer with its own packet protection. TLS
//! handshake messages are carried in QUIC CRYPTO frames without TLS record
//! headers. This module adapts tls.zig's NonBlock API — which expects TLS
//! records with 5-byte headers — to the raw-bytes interface that QUIC needs.
//!
//! Wrapping model:
//!   CRYPTO frame bytes (raw TLS handshake) → add 5-byte TLS record header
//!                                          → feed to tls.zig NonBlock.run()
//!   tls.zig NonBlock.run() output          → strip 5-byte TLS record headers
//!                                          → place in CRYPTO frames
//!
//! Key levels:
//!   After the Initial flight, tls.zig derives Handshake keys internally.
//!   After the Handshake flight, it derives the 1-RTT (Application) keys.
//!   The connection layer extracts these keys via `handshakeKeys()` /
//!   `appKeys()` to switch encryption levels.

const std = @import("std");
const keys = @import("keys.zig");
const varint = @import("../varint.zig");

/// Maximum bytes we buffer for a single crypto level's send queue.
pub const send_buf_len = 4096;
/// Maximum bytes we buffer for a single crypto level's recv queue.
pub const recv_buf_len = 4096;

/// TLS content-type for Handshake messages (RFC 8446 §5.1)
const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
/// TLS 1.2 legacy version used in record headers
const TLS_LEGACY_VERSION: u16 = 0x0303;

/// A simple FIFO byte buffer.
pub const ByteBuffer = struct {
    buf: [recv_buf_len]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    pub fn write(self: *ByteBuffer, data: []const u8) error{Full}!void {
        if (self.end + data.len > self.buf.len) return error.Full;
        @memcpy(self.buf[self.end .. self.end + data.len], data);
        self.end += data.len;
    }

    pub fn read(self: *ByteBuffer, out: []u8) usize {
        const available = self.end - self.start;
        const n = @min(available, out.len);
        @memcpy(out[0..n], self.buf[self.start .. self.start + n]);
        self.start += n;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
        return n;
    }

    pub fn readableSlice(self: *const ByteBuffer) []const u8 {
        return self.buf[self.start..self.end];
    }

    pub fn consume(self: *ByteBuffer, n: usize) void {
        self.start += n;
        if (self.start >= self.end) {
            self.start = 0;
            self.end = 0;
        }
    }

    pub fn len(self: *const ByteBuffer) usize {
        return self.end - self.start;
    }

    pub fn isEmpty(self: *const ByteBuffer) bool {
        return self.start == self.end;
    }
};

/// Wrap raw TLS handshake bytes in a TLS record header (content-type=Handshake).
/// `out` must have at least `data.len + 5` bytes.
pub fn wrapRecord(out: []u8, data: []const u8) usize {
    if (data.len == 0) return 0;
    out[0] = TLS_CONTENT_HANDSHAKE;
    std.mem.writeInt(u16, out[1..3], TLS_LEGACY_VERSION, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(data.len), .big);
    @memcpy(out[5 .. 5 + data.len], data);
    return 5 + data.len;
}

/// Strip TLS record headers from `input` and collect raw handshake bytes into `out`.
/// Returns bytes written to `out`.
pub fn stripRecords(out: []u8, input: []const u8) usize {
    var pos: usize = 0;
    var out_pos: usize = 0;
    while (pos + 5 <= input.len) {
        // Skip content type (1) and legacy version (2)
        pos += 3;
        const length = std.mem.readInt(u16, input[pos..][0..2], .big);
        pos += 2;
        if (pos + length > input.len) break;
        if (out_pos + length <= out.len) {
            @memcpy(out[out_pos .. out_pos + length], input[pos .. pos + length]);
            out_pos += length;
        }
        pos += length;
    }
    return out_pos;
}

/// TLS `quic_transport_parameters` extension type, RFC 9000 §18.2 / RFC 9001 §8.2.
///
/// 0xffa5 was the draft-29 codepoint; RFC 9000 standardized it as 0x0039
/// (57). All current QUIC v1 implementations on the wire (quic-go used by
/// go-libp2p, quinn used by rust-libp2p, ngtcp2, msquic) speak 0x0039,
/// so we must too — otherwise the peer never sees our transport params
/// in EncryptedExtensions and aborts the handshake with
/// `tls: server did not send a quic_transport_parameters extension`.
pub const TRANSPORT_PARAMS_EXT_TYPE: u16 = 0x0039;
/// Pre-RFC draft extension type; still accepted from peers (quinn/rustls interop).
pub const TRANSPORT_PARAMS_EXT_TYPE_DRAFT: u16 = 0xffa5;

/// Options for encoding the QUIC transport parameters TLS extension (RFC 9000 §18).
pub const TransportParamsOpts = struct {
    /// `initial_source_connection_id` (0x0f): SCID from this endpoint's first Initial.
    /// Required on every endpoint; peers (e.g. quinn) close with TRANSPORT_PARAMETER_ERROR if absent.
    initial_source_cid: []const u8,
    /// `original_destination_connection_id` (0x00): DCID from the peer's first Initial.
    /// Required on the server (RFC 9000 §7.4).
    original_destination_cid: ?[]const u8 = null,
    /// `retry_source_connection_id` (0x10): SCID from the server's Retry packet, if any.
    retry_source_cid: ?[]const u8 = null,
    /// `stateless_reset_token` (0x02): server-only; 16 bytes used by the peer
    /// to validate stateless resets we emit (RFC 9000 §10.3).
    stateless_reset_token: ?[16]u8 = null,
    /// `active_connection_id_limit` (0x0e): how many concurrent CIDs we are
    /// willing to store for the peer. RFC 9000 §18.2 default is 2; we
    /// advertise a larger pool so the peer can rotate freely.
    active_connection_id_limit: u64 = 4,
    /// `max_udp_payload_size` (0x03): largest UDP payload we are willing to
    /// receive on this connection. Bounded by [1200, 65527] per RFC 9000
    /// §18.2; values outside that range MUST be treated as TRANSPORT_PARAMETER_ERROR
    /// by a compliant peer. Default 0 = omit (peer assumes the §18.2 default
    /// of 65527). Callers should pass the connection's configured
    /// `max_udp_payload` so the peer doesn't send packets we can't reassemble
    /// on links with a smaller MTU.
    max_udp_payload_size: u64 = 0,
    /// `disable_active_migration` (0x0c): length-0 flag. When true we tell
    /// the peer not to use addresses other than the one used during the
    /// handshake. zquic supports active migration (gated on the `--migrate`
    /// example flag), so the default is false — embedders that know they
    /// won't migrate can opt in.
    disable_active_migration: bool = false,
    /// `preferred_address` (0x0d): server-only; alternate address + CID + reset
    /// token for active migration (RFC 9000 §9.6 / §18.2).
    preferred_address: ?PreferredAddressTp = null,
    /// `initial_max_data` (0x04): connection-level flow-control window.
    /// Default 1 MiB — conservative for memory; libp2p preset raises this.
    initial_max_data: u64 = 1_048_576,
    /// `initial_max_stream_data_bidi_local` (0x05).
    initial_max_stream_data_bidi_local: u64 = 262_144,
    /// `initial_max_stream_data_bidi_remote` (0x06).
    initial_max_stream_data_bidi_remote: u64 = 262_144,
    /// `initial_max_stream_data_uni` (0x07).
    initial_max_stream_data_uni: u64 = 262_144,
    /// `initial_max_streams_bidi` (0x08).
    initial_max_streams_bidi: u64 = 1000,
    /// `initial_max_streams_uni` (0x09).
    initial_max_streams_uni: u64 = 1000,
    /// RFC 9287 `grease_quic_bit` (0x2ab2): advertise tolerance for greased
    /// short-header QUIC bits from the peer.  Off by default so legacy quinn
    /// interop images that mishandle 0x2ab2 still complete handshakes; opt in
    /// explicitly when the peer is known to support RFC 9287.
    grease_quic_bit: bool = false,
    /// RFC 9221 `max_datagram_frame_size` (0x20).  Omitted when zero (disabled).
    max_datagram_frame_size: u64 = 0,
    /// draft-ietf-quic-ack-frequency `min_ack_delay` (0xff04de1b), in
    /// MICROSECONDS.  Advertising it signals support for ACK_FREQUENCY /
    /// IMMEDIATE_ACK frames and obligates us to honor them.  Omitted when
    /// zero.  Default 1 ms — matches the drive-loop ACK granularity.  Must
    /// not exceed our advertised max_ack_delay (25 ms).
    min_ack_delay_us: u64 = 1000,
};

/// Preset transport-parameter profiles for common embedders.
pub const TransportParamsPreset = enum {
    /// zquic defaults (1 MiB conn / 256 KiB stream / 1000 streams).
    default,
    /// libp2p-quic / gossipsub bulk profile (15 MiB conn / 10 MiB stream).
    libp2p,
};

/// Build [`TransportParamsOpts`] for `preset`, filling libp2p-quic-aligned limits when requested.
pub fn transportParamsForPreset(
    preset: TransportParamsPreset,
    initial_source_cid: []const u8,
    max_udp_payload_size: u64,
) TransportParamsOpts {
    var opts = TransportParamsOpts{
        .initial_source_cid = initial_source_cid,
        .max_udp_payload_size = max_udp_payload_size,
    };
    switch (preset) {
        .default => {},
        .libp2p => {
            // libp2p-quic Config::new defaults are quinn stream_receive_window =
            // 10 MiB / receive_window = 15 MiB. We advertise LARGER windows than
            // that baseline because the long-lived persistent `/meshsub` gossip
            // stream accumulates offset continuously: when a node's drive thread
            // reads that stream slowly under a full-mesh load, the recv window
            // stops extending and the *sender* stalls — which on the live devnet
            // wedged the stream after 20s and dropped peers. A larger window
            // (16 MiB/stream, 24 MiB/conn) absorbs more transient read-lag
            // before the sender stalls. Advertising bigger limits is always
            // interop-safe (the peer simply may send more); memory is a credit,
            // bounded by the conn window and only allocated as bytes actually
            // arrive (worst case ~24 MiB x peers, only if a drive thread is
            // fully stalled). NOTE: this only widens the headroom — the real
            // fix for a *sustained* slow reader is receiver throughput / lower
            // gossip volume (e.g. mesh_n_low), not a bigger buffer.
            opts.initial_max_data = 24_000_000;
            opts.initial_max_stream_data_bidi_local = 16_000_000;
            opts.initial_max_stream_data_bidi_remote = 16_000_000;
            opts.initial_max_stream_data_uni = 16_000_000;
            opts.initial_max_streams_bidi = 256;
            opts.initial_max_streams_uni = 0;
        },
    }
    return opts;
}

fn writeParamVarint(
    buf: []u8,
    pos: usize,
    id: u64,
    val: u64,
) (varint.EncodeError || varint.DecodeError)!usize {
    var w_pos = pos;
    var id_buf: [8]u8 = undefined;
    const id_enc = try varint.encode(&id_buf, id);
    @memcpy(buf[w_pos .. w_pos + id_enc.len], id_enc);
    w_pos += id_enc.len;
    var val_buf: [8]u8 = undefined;
    const val_enc = try varint.encode(&val_buf, val);
    var len_buf: [8]u8 = undefined;
    const len_enc = try varint.encode(&len_buf, val_enc.len);
    @memcpy(buf[w_pos .. w_pos + len_enc.len], len_enc);
    w_pos += len_enc.len;
    @memcpy(buf[w_pos .. w_pos + val_enc.len], val_enc);
    w_pos += val_enc.len;
    return w_pos;
}

fn writeParamBytes(buf: []u8, pos: usize, id: u64, value: []const u8) (varint.EncodeError || varint.DecodeError)!usize {
    var w_pos = pos;
    var id_buf: [8]u8 = undefined;
    const id_enc = try varint.encode(&id_buf, id);
    @memcpy(buf[w_pos .. w_pos + id_enc.len], id_enc);
    w_pos += id_enc.len;
    var len_buf: [8]u8 = undefined;
    const len_enc = try varint.encode(&len_buf, value.len);
    @memcpy(buf[w_pos .. w_pos + len_enc.len], len_enc);
    w_pos += len_enc.len;
    @memcpy(buf[w_pos .. w_pos + value.len], value);
    w_pos += value.len;
    return w_pos;
}

/// Encode a preferred_address transport parameter body (RFC 9000 §18.2).
pub fn encodePreferredAddress(pa: PreferredAddressTp, out: []u8) usize {
    var pos: usize = 0;
    @memcpy(out[pos .. pos + 4], &pa.ipv4);
    pos += 4;
    std.mem.writeInt(u16, out[pos..][0..2], pa.ipv4_port, .big);
    pos += 2;
    @memcpy(out[pos .. pos + 16], &pa.ipv6);
    pos += 16;
    std.mem.writeInt(u16, out[pos..][0..2], pa.ipv6_port, .big);
    pos += 2;
    out[pos] = pa.connection_id_len;
    pos += 1;
    @memcpy(out[pos .. pos + pa.connection_id_len], pa.connection_id[0..pa.connection_id_len]);
    pos += pa.connection_id_len;
    @memcpy(out[pos .. pos + 16], &pa.stateless_reset_token);
    pos += 16;
    return pos;
}

/// Build QUIC transport parameters for ClientHello or EncryptedExtensions.
pub fn buildTransportParams(out: []u8, opts: TransportParamsOpts) (varint.EncodeError || varint.DecodeError)!usize {
    var pos: usize = 0;

    pos = try writeParamVarint(out, pos, 0x01, 30_000); // max_idle_timeout
    pos = try writeParamVarint(out, pos, 0x04, opts.initial_max_data);
    pos = try writeParamVarint(out, pos, 0x05, opts.initial_max_stream_data_bidi_local);
    pos = try writeParamVarint(out, pos, 0x06, opts.initial_max_stream_data_bidi_remote);
    pos = try writeParamVarint(out, pos, 0x07, opts.initial_max_stream_data_uni);
    pos = try writeParamVarint(out, pos, 0x08, opts.initial_max_streams_bidi);
    pos = try writeParamVarint(out, pos, 0x09, opts.initial_max_streams_uni);
    // ack_delay_exponent (0x0a): we encode ACK Delay with the §18.2 default
    // exponent of 3, so advertise 3 explicitly. Without this the peer
    // assumes 3 anyway, but quinn double-checks the value when present.
    pos = try writeParamVarint(out, pos, 0x0a, 3);
    // max_ack_delay (0x0b): upper bound on how long we'll batch ACKs before
    // sending. 25 ms matches the §18.2 default and our actual ACK timer.
    pos = try writeParamVarint(out, pos, 0x0b, 25);
    // active_connection_id_limit (0x0e): we will accept this many distinct
    // CIDs from the peer; lets the peer rotate / migrate without exhausting.
    pos = try writeParamVarint(out, pos, 0x0e, opts.active_connection_id_limit);
    // max_udp_payload_size (0x03): the largest UDP payload we are willing to
    // receive on this connection (RFC 9000 §18.2). Only emitted when the
    // caller passes a non-zero value; an absent param signals the §18.2
    // default of 65527 to the peer.
    if (opts.max_udp_payload_size != 0) {
        pos = try writeParamVarint(out, pos, 0x03, opts.max_udp_payload_size);
    }
    // disable_active_migration (0x0c): length-0 flag indicating we will not
    // initiate active migration. Only emitted when the caller opts in.
    if (opts.disable_active_migration) {
        pos = try writeParamBytes(out, pos, 0x0c, &[_]u8{});
    }
    if (opts.preferred_address) |pa| {
        var pa_buf: [64]u8 = undefined;
        const pa_len = encodePreferredAddress(pa, &pa_buf);
        pos = try writeParamBytes(out, pos, 0x0d, pa_buf[0..pa_len]);
    }

    if (opts.original_destination_cid) |odcid| {
        pos = try writeParamBytes(out, pos, 0x00, odcid);
    }
    if (opts.stateless_reset_token) |srt| {
        pos = try writeParamBytes(out, pos, 0x02, &srt);
    }
    pos = try writeParamBytes(out, pos, 0x0f, opts.initial_source_cid);
    if (opts.retry_source_cid) |rscid| {
        pos = try writeParamBytes(out, pos, 0x10, rscid);
    }
    // RFC 9287: grease_quic_bit (0x2ab2) — length-0 flag.
    if (opts.grease_quic_bit) {
        pos = try writeParamBytes(out, pos, 0x2ab2, &[_]u8{});
    }
    // RFC 9221: max_datagram_frame_size (0x20).
    if (opts.max_datagram_frame_size > 0) {
        pos = try writeParamVarint(out, pos, 0x20, opts.max_datagram_frame_size);
    }
    // draft-ietf-quic-ack-frequency: min_ack_delay (0xff04de1b), microseconds.
    if (opts.min_ack_delay_us > 0) {
        pos = try writeParamVarint(out, pos, 0xff04de1b, opts.min_ack_delay_us);
    }
    return pos;
}

/// Build transport parameters with only flow-control limits (legacy test helper).
pub fn buildClientTransportParams(out: []u8) (varint.EncodeError || varint.DecodeError)!usize {
    const placeholder_cid = [_]u8{0} ** 8;
    return buildTransportParams(out, .{ .initial_source_cid = &placeholder_cid });
}

/// Subset of RFC 9000 §18.2 transport parameters relevant for runtime behavior.
///
/// Only the fields whose absence would cause us to violate the peer's limits
/// or compute a wrong PTO are surfaced here. Connection-id parameters
/// (`original_destination`, `initial_source`, `retry_source`) are validated
/// elsewhere as part of the handshake check; we do not retain them here.
pub const PeerTransportParams = struct {
    /// 0x04 — peer's connection-level receive window. Caps the cumulative
    /// stream-data bytes we may have in flight to the peer (RFC 9000 §4.1).
    /// Default 0 (per spec) — peer must advertise a non-zero value before
    /// we may send any STREAM data.
    initial_max_data: u64 = 0,
    /// 0x05 — peer's per-stream receive window for streams the peer opens
    /// and we send on (locally-initiated bidi from peer's perspective →
    /// remotely-initiated bidi from ours).
    initial_max_stream_data_bidi_local: u64 = 0,
    /// 0x06 — peer's per-stream receive window for streams we initiate
    /// (remotely-initiated bidi from peer's perspective → locally-initiated
    /// bidi from ours).
    initial_max_stream_data_bidi_remote: u64 = 0,
    /// 0x07 — peer's per-stream receive window for unidirectional streams
    /// we initiate.
    initial_max_stream_data_uni: u64 = 0,
    /// 0x08 — max bidirectional streams the peer permits us to open.
    initial_max_streams_bidi: u64 = 0,
    /// 0x09 — max unidirectional streams the peer permits us to open.
    initial_max_streams_uni: u64 = 0,
    /// 0x01 — peer's idle timeout in milliseconds. The connection's effective
    /// idle timeout is `min(local, peer)` per RFC 9000 §10.1.
    max_idle_timeout_ms: u64 = 0,
    /// 0x0a — exponent for ACK-Delay encoding in the peer's ACK frames
    /// (RFC 9000 §13.2.5). Defaults to 3 if absent.
    ack_delay_exponent: u8 = 3,
    /// 0x0b — peer's max_ack_delay in milliseconds. Used by our PTO
    /// calculation (RFC 9002 §6.2.1). Defaults to 25 ms if absent.
    max_ack_delay_ms: u64 = 25,
    /// 0x0c — peer requested no active migration. Empty (length-0) value.
    disable_active_migration: bool = false,
    /// 0x0e — number of distinct CIDs the peer is willing to store for us.
    /// Defaults to 2 if absent.
    active_connection_id_limit: u64 = 2,
    /// 0x03 — peer's max receive UDP payload size. Defaults to 65527 if absent.
    max_udp_payload_size: u64 = 65527,
    /// 0x0d — server-advertised preferred address (RFC 9000 §9.6).  Servers
    /// only; clients sending this MUST be treated as PROTOCOL_VIOLATION
    /// (§18.2), but this parser is permissive and surfaces whatever it
    /// finds — call sites enforce role.  `null` when the param is absent
    /// or the body is malformed.
    preferred_address: ?PreferredAddressTp = null,
    /// RFC 9287 `grease_quic_bit` (0x2ab2): peer tolerates greased QUIC bit.
    grease_quic_bit: bool = false,
    /// 0x20 — RFC 9221 max DATAGRAM frame payload size.  Zero when absent.
    max_datagram_frame_size: u64 = 0,
    /// 0xff04de1b — draft-ietf-quic-ack-frequency min_ack_delay in
    /// MICROSECONDS.  Zero when absent (peer does not support the extension).
    min_ack_delay_us: u64 = 0,
};

/// On-wire layout of the preferred_address transport parameter (RFC 9000
/// §18.2).  Mirrors `migration.PreferredAddress` but kept inside the
/// transport-param module so the parser does not depend on the higher-level
/// migration types.
pub const PreferredAddressTp = struct {
    ipv4: [4]u8,
    ipv4_port: u16,
    ipv6: [16]u8,
    ipv6_port: u16,
    connection_id_len: u8,
    connection_id: [20]u8,
    stateless_reset_token: [16]u8,

    pub fn hasIpv4(self: *const PreferredAddressTp) bool {
        return self.ipv4_port != 0 or !std.mem.allEqual(u8, &self.ipv4, 0);
    }

    pub fn hasIpv6(self: *const PreferredAddressTp) bool {
        return self.ipv6_port != 0 or !std.mem.allEqual(u8, &self.ipv6, 0);
    }
};

/// Parse the encoded preferred_address transport-parameter body (RFC 9000
/// §18.2).  Returns `null` if the body is shorter than the fixed prefix or
/// the embedded connection-id length overflows the value buffer.
fn parsePreferredAddress(value: []const u8) ?PreferredAddressTp {
    // Fixed prefix: 4 (v4) + 2 (v4 port) + 16 (v6) + 2 (v6 port) + 1 (cid_len)
    //             + 16 (reset token) = 41 bytes + connection_id.
    if (value.len < 41) return null;
    var pa: PreferredAddressTp = .{
        .ipv4 = undefined,
        .ipv4_port = 0,
        .ipv6 = undefined,
        .ipv6_port = 0,
        .connection_id_len = 0,
        .connection_id = .{0} ** 20,
        .stateless_reset_token = undefined,
    };
    var p: usize = 0;
    @memcpy(&pa.ipv4, value[p .. p + 4]);
    p += 4;
    pa.ipv4_port = std.mem.readInt(u16, value[p..][0..2], .big);
    p += 2;
    @memcpy(&pa.ipv6, value[p .. p + 16]);
    p += 16;
    pa.ipv6_port = std.mem.readInt(u16, value[p..][0..2], .big);
    p += 2;
    const cid_len = value[p];
    p += 1;
    if (cid_len > 20) return null;
    if (p + cid_len + 16 > value.len) return null;
    pa.connection_id_len = cid_len;
    @memcpy(pa.connection_id[0..cid_len], value[p .. p + cid_len]);
    p += cid_len;
    @memcpy(&pa.stateless_reset_token, value[p .. p + 16]);
    return pa;
}

/// Parse the encoded `quic_transport_parameters` TLS extension body
/// (RFC 9000 §18). Unknown ids are skipped per §18.1. Reserved transport
/// parameters (id mod 31 == 27) are accepted and ignored.
pub fn parseTransportParams(bytes: []const u8) varint.DecodeError!PeerTransportParams {
    var out: PeerTransportParams = .{};
    var pos: usize = 0;
    while (pos < bytes.len) {
        const id_r = try varint.decode(bytes[pos..]);
        pos += id_r.len;
        if (pos >= bytes.len) return error.BufferTooShort;
        const len_r = try varint.decode(bytes[pos..]);
        pos += len_r.len;
        const value_len = try varint.lenToUsize(len_r.value);
        if (pos + value_len > bytes.len) return error.BufferTooShort;
        const value = bytes[pos .. pos + value_len];
        pos += value_len;

        switch (id_r.value) {
            0x01 => out.max_idle_timeout_ms = readVarintField(value) catch continue,
            0x03 => out.max_udp_payload_size = readVarintField(value) catch continue,
            0x04 => out.initial_max_data = readVarintField(value) catch continue,
            0x05 => out.initial_max_stream_data_bidi_local = readVarintField(value) catch continue,
            0x06 => out.initial_max_stream_data_bidi_remote = readVarintField(value) catch continue,
            0x07 => out.initial_max_stream_data_uni = readVarintField(value) catch continue,
            0x08 => out.initial_max_streams_bidi = readVarintField(value) catch continue,
            0x09 => out.initial_max_streams_uni = readVarintField(value) catch continue,
            0x0a => {
                const v = readVarintField(value) catch continue;
                if (v <= 20) out.ack_delay_exponent = @intCast(v);
            },
            0x0b => out.max_ack_delay_ms = readVarintField(value) catch continue,
            0x0c => out.disable_active_migration = (value_len == 0),
            0x0d => out.preferred_address = parsePreferredAddress(value),
            0x0e => out.active_connection_id_limit = readVarintField(value) catch continue,
            0x2ab2 => out.grease_quic_bit = (value_len == 0),
            0x20 => out.max_datagram_frame_size = readVarintField(value) catch continue,
            0xff04de1b => out.min_ack_delay_us = readVarintField(value) catch continue,
            else => {}, // unknown / reserved / connection-id params are not surfaced here
        }
    }
    return out;
}

/// Decode a single varint that occupies `value` exactly.
/// Returns an error if the buffer is empty or has trailing bytes.
fn readVarintField(value: []const u8) varint.DecodeError!u64 {
    if (value.len == 0) return error.BufferTooShort;
    const r = try varint.decode(value);
    if (r.len != value.len) return error.NonMinimalEncoding;
    return r.value;
}

test "transport params: round-trip varint fields" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const n = try buildTransportParams(&buf, .{ .initial_source_cid = &cid });
    const parsed = try parseTransportParams(buf[0..n]);
    try testing.expectEqual(@as(u64, 30_000), parsed.max_idle_timeout_ms);
    try testing.expectEqual(@as(u64, 1_048_576), parsed.initial_max_data);
    try testing.expectEqual(@as(u64, 262_144), parsed.initial_max_stream_data_bidi_local);
    try testing.expectEqual(@as(u64, 262_144), parsed.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(@as(u64, 262_144), parsed.initial_max_stream_data_uni);
    try testing.expectEqual(@as(u64, 1000), parsed.initial_max_streams_bidi);
    try testing.expectEqual(@as(u64, 1000), parsed.initial_max_streams_uni);
    try testing.expectEqual(@as(u8, 3), parsed.ack_delay_exponent);
    try testing.expectEqual(@as(u64, 25), parsed.max_ack_delay_ms);
    try testing.expectEqual(@as(u64, 4), parsed.active_connection_id_limit);
    // We don't emit `disable_active_migration`; check the default here.
    try testing.expectEqual(false, parsed.disable_active_migration);
    // draft-ietf-quic-ack-frequency: advertised by default at 1 ms.
    try testing.expectEqual(@as(u64, 1000), parsed.min_ack_delay_us);
}

test "transport params: min_ack_delay omitted when zero" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const cid = [_]u8{0xaa};
    const n = try buildTransportParams(&buf, .{
        .initial_source_cid = &cid,
        .min_ack_delay_us = 0,
    });
    const parsed = try parseTransportParams(buf[0..n]);
    try testing.expectEqual(@as(u64, 0), parsed.min_ack_delay_us);
}

test "transport params: max_datagram_frame_size round-trip" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const n = try buildTransportParams(&buf, .{
        .initial_source_cid = &cid,
        .max_datagram_frame_size = 1200,
    });
    const parsed = try parseTransportParams(buf[0..n]);
    try testing.expectEqual(@as(u64, 1200), parsed.max_datagram_frame_size);
}

test "transport params: unknown ids are skipped" {
    const testing = std.testing;
    // id=0x21 (unknown, 1-byte varint), len=2, value=2 opaque bytes.
    // Followed by id=0x04 (initial_max_data), len=2, value=0x44 0x80 (varint = 0x0480 = 1152).
    const bytes = [_]u8{ 0x21, 0x02, 0xaa, 0xbb, 0x04, 0x02, 0x44, 0x80 };
    const parsed = try parseTransportParams(&bytes);
    try testing.expectEqual(@as(u64, 0x0480), parsed.initial_max_data);
}

test "transport params: disable_active_migration is a length-0 flag" {
    const testing = std.testing;
    const bytes = [_]u8{ 0x0c, 0x00 };
    const parsed = try parseTransportParams(&bytes);
    try testing.expect(parsed.disable_active_migration);
}

test "transport params: grease_quic_bit round-trip when enabled" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const n = try buildTransportParams(&buf, .{
        .initial_source_cid = &cid,
        .grease_quic_bit = true,
    });
    const parsed = try parseTransportParams(buf[0..n]);
    try testing.expect(parsed.grease_quic_bit);
}

test "transport params: ack_delay_exponent above 20 is clamped to default" {
    const testing = std.testing;
    // id=0x0a, len=1, value=21 (illegal — RFC 9000 §18.2 bounds it to 20).
    const bytes = [_]u8{ 0x0a, 0x01, 0x15 };
    const parsed = try parseTransportParams(&bytes);
    try testing.expectEqual(@as(u8, 3), parsed.ack_delay_exponent);
}

test "transport params: truncated value is rejected" {
    const testing = std.testing;
    // id=0x04 (initial_max_data), len=4, but only 2 bytes of payload follow.
    const bytes = [_]u8{ 0x04, 0x04, 0x44, 0x80 };
    try testing.expectError(error.BufferTooShort, parseTransportParams(&bytes));
}

test "transport params: max_udp_payload_size emitted only when opted in" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    // Default opts → 0x03 absent → peer falls back to the §18.2 default 65527.
    {
        const n = try buildTransportParams(&buf, .{ .initial_source_cid = &cid });
        const parsed = try parseTransportParams(buf[0..n]);
        try testing.expectEqual(@as(u64, 65527), parsed.max_udp_payload_size);
    }
    // Opt in with our actual receive MTU; round-trip the exact value.
    {
        const n = try buildTransportParams(&buf, .{
            .initial_source_cid = &cid,
            .max_udp_payload_size = 1500,
        });
        const parsed = try parseTransportParams(buf[0..n]);
        try testing.expectEqual(@as(u64, 1500), parsed.max_udp_payload_size);
    }
}

test "transport params: disable_active_migration emitted only when opted in" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    // Default opts → 0x0c absent → peer reads false.
    {
        const n = try buildTransportParams(&buf, .{ .initial_source_cid = &cid });
        const parsed = try parseTransportParams(buf[0..n]);
        try testing.expectEqual(false, parsed.disable_active_migration);
    }
    // Opt in → 0x0c emitted as a length-0 flag → peer reads true.
    {
        const n = try buildTransportParams(&buf, .{
            .initial_source_cid = &cid,
            .disable_active_migration = true,
        });
        const parsed = try parseTransportParams(buf[0..n]);
        try testing.expect(parsed.disable_active_migration);
        // Bytes-on-wire check: the emitted frame is `0x0c 0x00` (id varint
        // 0x0c, length varint 0). The buffer must contain that exact pair.
        try testing.expect(std.mem.indexOf(u8, buf[0..n], &.{ 0x0c, 0x00 }) != null);
    }
}

test "transport params: preferred_address encode round-trip" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const cid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const pa = PreferredAddressTp{
        .ipv4 = .{ 192, 0, 2, 1 },
        .ipv4_port = 4433,
        .ipv6 = .{0} ** 16,
        .ipv6_port = 0,
        .connection_id_len = 8,
        .connection_id = cid ++ ([_]u8{0} ** 12),
        .stateless_reset_token = .{0xab} ** 16,
    };
    const n = try buildTransportParams(&buf, .{
        .initial_source_cid = &cid,
        .preferred_address = pa,
    });
    const parsed = try parseTransportParams(buf[0..n]);
    try testing.expect(parsed.preferred_address != null);
    const got = parsed.preferred_address.?;
    try testing.expectEqual(@as(u16, 4433), got.ipv4_port);
    try testing.expectEqual(@as(u8, 8), got.connection_id_len);
}

test "transport params: preferred_address (0x0d) parses ipv4 + cid + reset token" {
    const testing = std.testing;

    // Hand-encode a minimal preferred_address TP body: ipv4 only, 8-byte CID.
    // Fixed layout: 4 + 2 + 16 + 2 + 1 + 8 + 16 = 49 bytes of value.
    var value: [49]u8 = undefined;
    var vp: usize = 0;
    @memcpy(value[vp .. vp + 4], &[_]u8{ 192, 0, 2, 1 });
    vp += 4;
    std.mem.writeInt(u16, value[vp..][0..2], 4433, .big);
    vp += 2;
    @memset(value[vp .. vp + 16], 0); // no ipv6
    vp += 16;
    std.mem.writeInt(u16, value[vp..][0..2], 0, .big);
    vp += 2;
    value[vp] = 8; // cid_len
    vp += 1;
    @memcpy(value[vp .. vp + 8], &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });
    vp += 8;
    @memset(value[vp .. vp + 16], 0xab); // reset token

    // Wrap in TP framing: id 0x0d (varint), length 49 (varint), then value.
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    const id_e = try varint.encode(buf[pos..], 0x0d);
    pos += id_e.len;
    const len_e = try varint.encode(buf[pos..], value.len);
    pos += len_e.len;
    @memcpy(buf[pos .. pos + value.len], &value);
    pos += value.len;

    const parsed = try parseTransportParams(buf[0..pos]);
    try testing.expect(parsed.preferred_address != null);
    const pa = parsed.preferred_address.?;
    try testing.expect(pa.hasIpv4());
    try testing.expect(!pa.hasIpv6());
    try testing.expectEqual(@as(u16, 4433), pa.ipv4_port);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &pa.ipv4);
    try testing.expectEqual(@as(u8, 8), pa.connection_id_len);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        pa.connection_id[0..8],
    );
    try testing.expectEqual(@as(u8, 0xab), pa.stateless_reset_token[0]);
}

test "transport params: preferred_address absent → null" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const n = try buildTransportParams(&buf, .{ .initial_source_cid = &cid });
    const parsed = try parseTransportParams(buf[0..n]);
    try testing.expect(parsed.preferred_address == null);
}

test "transport params: preferred_address truncated body → null (silent skip)" {
    const testing = std.testing;

    // 30-byte value: shorter than the 41-byte fixed prefix.
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    const id_e = try varint.encode(buf[pos..], 0x0d);
    pos += id_e.len;
    const len_e = try varint.encode(buf[pos..], 30);
    pos += len_e.len;
    @memset(buf[pos .. pos + 30], 0);
    pos += 30;

    const parsed = try parseTransportParams(buf[0..pos]);
    try testing.expect(parsed.preferred_address == null);
}

/// Tracks CRYPTO stream offsets per encryption level for reassembly.
pub const CryptoStream = struct {
    /// Bytes received so far (next expected offset)
    recv_offset: u64 = 0,
    /// Bytes sent so far (next send offset)
    send_offset: u64 = 0,
    /// Pending received bytes (may arrive out of order)
    recv_buf: ByteBuffer = .{},
    /// Bytes ready to send
    send_buf: ByteBuffer = .{},
    /// Reorder buffer for out-of-order CRYPTO fragments.
    reorder: CryptoReorderBuf = .{},

    /// Feed received CRYPTO frame data into the stream.
    /// Out-of-order fragments are buffered in `reorder` and drained
    /// automatically once the gap is filled.
    pub fn feedRecv(self: *CryptoStream, offset: u64, data: []const u8) error{Full}!void {
        if (offset != self.recv_offset) {
            // Out-of-order: buffer for later reassembly.
            self.reorder.insert(offset, data);
            return;
        }
        // In-order segment: commit to recv_buf and advance offset.
        try self.recv_buf.write(data);
        self.recv_offset += data.len;
        // Drain any now-contiguous buffered segments.
        var drain_buf: [REORDER_SLOT_SIZE]u8 = undefined;
        while (true) {
            const n = self.reorder.take(self.recv_offset, &drain_buf);
            if (n == 0) break;
            self.recv_buf.write(drain_buf[0..n]) catch break; // buffer full
            self.recv_offset += n;
        }
    }

    /// Enqueue bytes to send as CRYPTO frames.
    pub fn enqueueSend(self: *CryptoStream, data: []const u8) error{Full}!void {
        try self.send_buf.write(data);
    }

    /// Take up to `max` bytes from the send queue.
    /// Returns the offset at which these bytes should appear and the data.
    pub fn takeSend(self: *CryptoStream, buf: []u8) struct { offset: u64, len: usize } {
        const n = self.send_buf.read(buf);
        const offset = self.send_offset;
        self.send_offset += n;
        return .{ .offset = offset, .len = n };
    }
};

// ---------------------------------------------------------------------------
// CRYPTO Frame Reorder Buffer
// ---------------------------------------------------------------------------

/// Maximum number of out-of-order segments held per encryption level.
pub const REORDER_SLOTS: usize = 128;
/// Maximum byte length of a single buffered CRYPTO/STREAM fragment.
/// Must cover `path_mtu.appStreamChunkBytes` (~1350 B) or `insert` drops the
/// segment and HTTP/0.9 downloads stall under NS3 loss (interop transfer).
pub const REORDER_SLOT_SIZE: usize = 1450;

const CryptoReorderSlot = struct {
    offset: u64 = 0,
    used: bool = false,
    len: usize = 0,
    data: [REORDER_SLOT_SIZE]u8 = undefined,
};

/// Small reorder buffer for CRYPTO frames that arrive out-of-order.
///
/// TLS handshake messages (especially the client Finished) can arrive before
/// their preceding fragments due to UDP reordering.  Without buffering, the
/// out-of-order fragment is silently dropped and the handshake stalls.
///
/// Usage (server, Initial level):
///   if (offset != expected_offset) {
///       conn.init_crypto_reorder.insert(offset, data);
///   } else {
///       process(data); expected_offset += data.len;
///       // Drain any now-contiguous buffered segments.
///       var drain_buf: [REORDER_SLOT_SIZE]u8 = undefined;
///       while (true) {
///           const n = conn.init_crypto_reorder.take(expected_offset, &drain_buf);
///           if (n == 0) break;
///           process(drain_buf[0..n]); expected_offset += n;
///       }
///   }
pub const CryptoReorderBuf = struct {
    slots: [REORDER_SLOTS]CryptoReorderSlot = [_]CryptoReorderSlot{.{}} ** REORDER_SLOTS,

    /// Buffer an out-of-order CRYPTO segment.
    /// Silently drops if the buffer is full or the segment exceeds REORDER_SLOT_SIZE.
    pub fn insert(self: *CryptoReorderBuf, offset: u64, data: []const u8) void {
        if (data.len > REORDER_SLOT_SIZE) return;
        // Idempotent: ignore duplicates.
        for (&self.slots) |*slot| {
            if (slot.used and slot.offset == offset) return;
        }
        // Find an empty slot.
        for (&self.slots) |*slot| {
            if (!slot.used) {
                slot.offset = offset;
                slot.len = data.len;
                slot.used = true;
                @memcpy(slot.data[0..data.len], data);
                return;
            }
        }
        // Buffer full — evict the segment with the LARGEST offset (furthest
        // from the contiguity frontier, so the least useful to `take`). The
        // previous policy evicted the SMALLEST offset — exactly the segment
        // the next drain needs — so a fragment storm (ngtcp2 retransmitting a
        // fragmented flight with new boundaries each round fills the slots
        // with distinct offsets) starved the frontier and wedged reassembly.
        // Only evict for a segment that is nearer the frontier than the
        // victim; an incoming far-future segment is dropped instead.
        var victim: usize = 0;
        for (1..REORDER_SLOTS) |i| {
            if (self.slots[i].used and self.slots[i].offset > self.slots[victim].offset) {
                victim = i;
            }
        }
        if (offset >= self.slots[victim].offset) return;
        self.slots[victim].offset = offset;
        self.slots[victim].len = data.len;
        self.slots[victim].used = true;
        @memcpy(self.slots[victim].data[0..data.len], data);
    }

    /// Return the buffered bytes that continue the contiguous stream at
    /// `next_offset`, copy them into `out`, and free the slot.  Returns the
    /// number of bytes, or 0 if nothing extends the stream.
    ///
    /// Overlap-aware: a slot whose range merely *covers* `next_offset`
    /// (`slot.offset <= next_offset < slot.offset + slot.len`) yields its tail
    /// from `next_offset` onward.  Peers that fragment a handshake message into
    /// many small CRYPTO frames (ngtcp2 / c-lean-libp2p) retransmit with
    /// DIFFERENT boundaries each round, so the contiguity frontier frequently
    /// lands mid-slot; an exact-offset match would leave those bytes
    /// unreachable until a boundary-aligned retransmit happened to arrive,
    /// stalling reassembly for several round trips.  Fully-consumed slots
    /// (`offset + len <= next_offset`) are freed in passing.
    pub fn take(self: *CryptoReorderBuf, next_offset: u64, out: []u8) usize {
        for (&self.slots) |*slot| {
            if (!slot.used) continue;
            const end = slot.offset + slot.len;
            if (end <= next_offset) {
                // Entirely below the frontier — a stale duplicate. Reclaim it.
                slot.used = false;
                continue;
            }
            if (slot.offset <= next_offset) {
                const skip: usize = @intCast(next_offset - slot.offset);
                const avail = slot.len - skip;
                const n = @min(avail, out.len);
                @memcpy(out[0..n], slot.data[skip..][0..n]);
                slot.used = false;
                return n;
            }
        }
        return 0;
    }
};

test "byte_buffer: write and read" {
    const testing = std.testing;
    var bb = ByteBuffer{};
    try bb.write("hello");
    try bb.write(" world");

    var out: [64]u8 = undefined;
    const n = bb.read(&out);
    try testing.expectEqualSlices(u8, "hello world", out[0..n]);
    try testing.expect(bb.isEmpty());
}

test "wrap_strip: record round-trip" {
    const testing = std.testing;
    const data = "TLSHandshake";

    var wrapped: [64]u8 = undefined;
    const w_len = wrapRecord(&wrapped, data);
    try testing.expectEqual(@as(usize, data.len + 5), w_len);
    try testing.expectEqual(@as(u8, TLS_CONTENT_HANDSHAKE), wrapped[0]);

    var stripped: [64]u8 = undefined;
    const s_len = stripRecords(&stripped, wrapped[0..w_len]);
    try testing.expectEqualSlices(u8, data, stripped[0..s_len]);
}

test "transport_params: builds non-empty" {
    var buf: [256]u8 = undefined;
    const n = try buildClientTransportParams(&buf);
    try std.testing.expect(n > 0);
}

test "transport_params: includes initial_source_connection_id" {
    const cid = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    var buf: [256]u8 = undefined;
    const n = try buildTransportParams(&buf, .{ .initial_source_cid = &cid });
    try std.testing.expect(n > 0);
    // id=0x0f varint is one byte 0x0f; value length 8 follows.
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], &.{ 0x0f, 0x08 }) != null);
}

test "crypto_stream: in-order feed" {
    const testing = std.testing;
    var cs = CryptoStream{};
    try cs.feedRecv(0, "abc");
    try cs.feedRecv(3, "def");
    try testing.expectEqual(@as(u64, 6), cs.recv_offset);
    try testing.expectEqual(@as(usize, 6), cs.recv_buf.len());
}

test "crypto_reorder_buf: insert and take" {
    const testing = std.testing;
    var rb = CryptoReorderBuf{};

    // Insert segment at offset 10, then take it.
    rb.insert(10, "hello");
    var out: [32]u8 = undefined;
    const n = rb.take(10, &out);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "hello", out[0..n]);

    // Slot should now be free — take again returns 0.
    try testing.expectEqual(@as(usize, 0), rb.take(10, &out));
}

test "crypto_reorder_buf: drain sequence" {
    const testing = std.testing;
    var rb = CryptoReorderBuf{};

    // Simulate out-of-order arrival: segment at offset 5 arrives before offset 0.
    rb.insert(5, "world");
    rb.insert(0, "hello");

    var expected_offset: u64 = 0;
    var out: [32]u8 = undefined;

    // Drain contiguous run starting at 0.
    var n = rb.take(expected_offset, &out);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "hello", out[0..n]);
    expected_offset += n;

    n = rb.take(expected_offset, &out);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "world", out[0..n]);
    expected_offset += n;

    try testing.expectEqual(@as(u64, 10), expected_offset);
    try testing.expectEqual(@as(usize, 0), rb.take(expected_offset, &out));
}

test "crypto_reorder_buf: take yields tail of a straddling slot" {
    const testing = std.testing;
    var rb = CryptoReorderBuf{};

    // A frame covering [0,10) is buffered while the frontier is already at 4
    // (a coarser earlier fragment delivered [0,4)). take must return the tail
    // [4,10) rather than nothing, so a peer that retransmits with different
    // fragment boundaries doesn't stall the stream.
    rb.insert(0, "0123456789");
    var out: [32]u8 = undefined;
    const n = rb.take(4, &out);
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqualSlices(u8, "456789", out[0..n]);
    // Slot consumed.
    try testing.expectEqual(@as(usize, 0), rb.take(10, &out));
}

test "crypto_reorder_buf: overflow evicts the FARTHEST segment, keeps near-frontier ones" {
    const testing = std.testing;
    var rb = CryptoReorderBuf{};

    // Fill every slot: offsets 10, 20, 30, ... (frontier is at 0).
    for (0..REORDER_SLOTS) |i| {
        rb.insert(@intCast((i + 1) * 10), "x");
    }
    // Buffer full. A NEAR-frontier segment must displace the farthest one,
    // not the nearest (the old policy evicted offset 10 — the very segment
    // the next drain needed — wedging fragmented-flight reassembly).
    rb.insert(5, "nn");
    var out: [32]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), rb.take(5, &out));
    try testing.expectEqualSlices(u8, "nn", out[0..2]);
    // And the near-frontier original (offset 10) survived the eviction.
    try testing.expectEqual(@as(usize, 1), rb.take(10, &out));

    // A far-future segment must NOT evict anything when full: refill the two
    // freed slots, then insert past the maximum — it is dropped.
    rb.insert(10, "a");
    rb.insert(15, "b");
    rb.insert(999_999, "z");
    try testing.expectEqual(@as(usize, 0), rb.take(999_999, &out));
}

test "crypto_reorder_buf: take reclaims fully-consumed stale slots" {
    const testing = std.testing;
    var rb = CryptoReorderBuf{};

    // Stale duplicate entirely below the frontier: must be freed, not matched.
    rb.insert(0, "abc"); // [0,3), frontier already past it
    var out: [32]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), rb.take(3, &out));
    // The slot was reclaimed, so a genuine future segment can now be taken.
    rb.insert(3, "def");
    const n = rb.take(3, &out);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u8, "def", out[0..n]);
}

test "crypto_stream: out-of-order feedRecv with reorder" {
    const testing = std.testing;
    var cs = CryptoStream{};
    // Feed segment at offset 3 first (out-of-order).
    try cs.feedRecv(3, "def");
    // recv_offset should NOT advance (gap at 0).
    try testing.expectEqual(@as(u64, 0), cs.recv_offset);
    try testing.expectEqual(@as(usize, 0), cs.recv_buf.len());
    // Now feed the missing segment at offset 0.
    try cs.feedRecv(0, "abc");
    // Both segments should now be delivered contiguously.
    try testing.expectEqual(@as(u64, 6), cs.recv_offset);
    try testing.expectEqual(@as(usize, 6), cs.recv_buf.len());
    var out: [16]u8 = undefined;
    const n = cs.recv_buf.read(&out);
    try testing.expectEqualSlices(u8, "abcdef", out[0..n]);
}
