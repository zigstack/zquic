//! zquic — a pure Zig implementation of QUIC (RFC 9000 / 9001 / 9002).
//!
//! Protocol coverage:
//!   - RFC 9000  QUIC: A UDP-Based Multiplexed and Secure Transport
//!   - RFC 9001  Using TLS to Secure QUIC
//!   - RFC 9002  QUIC Loss Detection and Congestion Control
//!   - RFC 9114  HTTP/3
//!   - RFC 9204  QPACK: Header Compression for HTTP/3

pub const varint = @import("varint.zig");
pub const types = @import("types.zig");
pub const packet = struct {
    pub const header = @import("packet/header.zig");
    pub const number = @import("packet/number.zig");
    pub const pkt = @import("packet/packet.zig");
    pub const retry = @import("packet/retry.zig");
    pub const version_negotiation = @import("packet/version_negotiation.zig");
};
pub const crypto = struct {
    pub const keys = @import("crypto/keys.zig");
    pub const aead = @import("crypto/aead.zig");
    pub const initial = @import("crypto/initial.zig");
    pub const quic_tls = @import("crypto/quic_tls.zig");
    pub const session = @import("crypto/session.zig");
    pub const key_update = @import("crypto/key_update.zig");
};
pub const loss = struct {
    pub const recovery = @import("loss/recovery.zig");
    pub const congestion = @import("loss/congestion.zig");
    pub const cubic = @import("loss/cubic.zig");
};
pub const tls = struct {
    pub const handshake = @import("tls/handshake.zig");
};
pub const transport = struct {
    pub const connection = @import("transport/connection.zig");
    pub const endpoint = @import("transport/endpoint.zig");
    pub const flow_control = @import("transport/flow_control.zig");
    pub const stream_manager = @import("transport/stream_manager.zig");
    pub const session_token = @import("transport/session_token.zig");
    pub const stats = @import("transport/stats.zig");
    pub const migration = @import("transport/migration.zig");
    pub const io = @import("transport/io.zig");
    pub const path_mtu = @import("transport/path_mtu.zig");
    pub const datagrams = @import("transport/datagrams.zig");
};
pub const http3 = struct {
    pub const frame = @import("http3/frame.zig");
    pub const qpack = @import("http3/qpack.zig");
    pub const connect = @import("http3/connect.zig");
};
pub const http09 = struct {
    pub const server = @import("http09/server.zig");
    pub const client = @import("http09/client.zig");
};
pub const qlog = struct {
    pub const writer = @import("qlog/writer.zig");
};
pub const frames = struct {
    pub const frame = @import("frames/frame.zig");
    pub const ack = @import("frames/ack.zig");
    pub const crypto_frame = @import("frames/crypto_frame.zig");
    pub const stream = @import("frames/stream.zig");
    pub const transport = @import("frames/transport.zig");
    pub const datagram = @import("frames/datagram.zig");
};

test {
    _ = @import("varint.zig");
    _ = @import("types.zig");
    _ = @import("packet/header.zig");
    _ = @import("packet/number.zig");
    _ = @import("packet/packet.zig");
    _ = @import("packet/retry.zig");
    _ = @import("packet/version_negotiation.zig");
    _ = @import("crypto/keys.zig");
    _ = @import("crypto/aead.zig");
    _ = @import("crypto/initial.zig");
    _ = @import("crypto/quic_tls.zig");
    _ = @import("crypto/session.zig");
    _ = @import("crypto/key_update.zig");
    _ = @import("tls/handshake.zig");
    _ = @import("loss/recovery.zig");
    _ = @import("loss/congestion.zig");
    _ = @import("loss/cubic.zig");
    _ = @import("transport/connection.zig");
    _ = @import("transport/endpoint.zig");
    _ = @import("transport/flow_control.zig");
    _ = @import("transport/stream_manager.zig");
    _ = @import("transport/session_token.zig");
    _ = @import("transport/stats.zig");
    _ = @import("transport/migration.zig");
    _ = @import("transport/raw_app_stream.zig");
    _ = @import("transport/io.zig");
    _ = @import("transport/path_mtu.zig");
    _ = @import("http3/frame.zig");
    _ = @import("http3/qpack.zig");
    _ = @import("http3/connect.zig");
    _ = @import("http09/server.zig");
    _ = @import("http09/client.zig");
    _ = @import("frames/frame.zig");
    _ = @import("frames/ack.zig");
    _ = @import("frames/crypto_frame.zig");
    _ = @import("frames/stream.zig");
    _ = @import("frames/transport.zig");
    _ = @import("frames/datagram.zig");
    _ = @import("transport/datagrams.zig");
    _ = @import("qlog/writer.zig");
}
