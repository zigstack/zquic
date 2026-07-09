//! QUIC-specific TLS 1.3 handshake (RFC 9001 §4).
//!
//! QUIC replaces the TLS record layer with QUIC CRYPTO frames. This module
//! implements TLS 1.3 handshake message parsing and building for QUIC — no
//! TLS record headers, no TLS-level AEAD. QUIC packet encryption provides
//! the confidentiality that TLS records would normally provide.
//!
//! Key schedule follows RFC 8446 §7.1:
//!
//!   early_secret     = HKDF-Extract("", 0)
//!   handshake_secret = HKDF-Extract(derive(early_secret), ecdhe_shared_key)
//!   master_secret    = HKDF-Extract(derive(handshake_secret), 0)
//!   traffic secrets  = HKDF-Expand-Label(secret, label, hash, 32)
//!
//! QUIC key derivation follows RFC 9001 §5.1:
//!
//!   quic_key = HKDF-Expand-Label(traffic_secret, "quic key", "", key_len)
//!   quic_iv  = HKDF-Expand-Label(traffic_secret, "quic iv",  "", iv_len)
//!   quic_hp  = HKDF-Expand-Label(traffic_secret, "quic hp",  "", key_len)

const std = @import("std");
const compat = @import("../compat.zig");
const crypto = std.crypto;
const keys_mod = @import("../crypto/keys.zig");
const quic_tls = @import("../crypto/quic_tls.zig");
const tls_vendor = @import("tls");

const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const Certificate = std.crypto.Certificate;

// TLS 1.3 handshake message types
pub const MSG_CLIENT_HELLO: u8 = 0x01;
pub const MSG_SERVER_HELLO: u8 = 0x02;
/// RFC 8446 §4.4.1 synthetic "message_hash" handshake type, used to rewrite the
/// transcript when a HelloRetryRequest is sent.
pub const MSG_MESSAGE_HASH: u8 = 0xFE;
pub const MSG_NEW_SESSION_TICKET: u8 = 0x04;
pub const MSG_ENCRYPTED_EXTENSIONS: u8 = 0x08;
pub const MSG_CERTIFICATE: u8 = 0x0b;
pub const MSG_CERTIFICATE_REQUEST: u8 = 0x0d;
pub const MSG_CERTIFICATE_VERIFY: u8 = 0x0f;
pub const MSG_FINISHED: u8 = 0x14;

// TLS extension types
pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXT_KEY_SHARE: u16 = 0x0033;
pub const EXT_QUIC_TRANSPORT_PARAMS: u16 = quic_tls.TRANSPORT_PARAMS_EXT_TYPE;
pub const EXT_QUIC_TRANSPORT_PARAMS_DRAFT: u16 = quic_tls.TRANSPORT_PARAMS_EXT_TYPE_DRAFT;

fn isQuicTransportParamsExt(ext_type: u16) bool {
    return ext_type == EXT_QUIC_TRANSPORT_PARAMS or ext_type == EXT_QUIC_TRANSPORT_PARAMS_DRAFT;
}
pub const EXT_PRE_SHARED_KEY: u16 = 0x0029;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
pub const EXT_EARLY_DATA: u16 = 0x002a;
/// RFC 8446 `signature_algorithms` (required in TLS 1.3 `CertificateRequest`).
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;

// TLS cipher suites
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// Named groups
pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_SECP256R1: u16 = 0x0017;

// TLS version
pub const TLS_VERSION_13: u16 = 0x0304;
pub const TLS_LEGACY_VERSION: u16 = 0x0303;

// TLS 1.3 signature schemes
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;

// ALPN for HTTP/3
pub const ALPN_H3 = "h3";
pub const ALPN_H09 = "hq-interop";

/// TLS 1.3 traffic secrets for QUIC key derivation.
pub const TrafficSecrets = struct {
    client_handshake: [32]u8 = [_]u8{0} ** 32,
    server_handshake: [32]u8 = [_]u8{0} ** 32,
    client_app: [32]u8 = [_]u8{0} ** 32,
    server_app: [32]u8 = [_]u8{0} ** 32,
};

/// Fields from ClientHello relevant to QUIC handshake.
pub const ClientHelloData = struct {
    random: [32]u8 = [_]u8{0} ** 32,
    session_id: [32]u8 = [_]u8{0} ** 32,
    session_id_len: u8 = 0,
    x25519_key: ?[32]u8 = null,
    /// True if the client listed X25519 (0x001d) in supported_groups, even
    /// when it did not send an X25519 key_share. Drives HelloRetryRequest.
    x25519_supported_group: bool = false,
    cipher_suite: u16 = TLS_AES_128_GCM_SHA256,
    quic_transport_params: ?struct { offset: usize, len: usize } = null,
    /// TLS extension type the client used for QUIC transport parameters.
    quic_transport_params_ext_type: u16 = EXT_QUIC_TRANSPORT_PARAMS,
    alpn_h3: bool = false,
    alpn_h09: bool = false,
    /// Copy of the ProtocolNameList inner bytes from the client's ALPN
    /// extension (`u8 len + proto`-repeated). Used by
    /// [`eeAlpnMatchingClientOffer`] to honor arbitrary preferred ALPN
    /// strings (e.g. `libp2p` for libp2p QUIC interop) without changing
    /// the wire format. 256 bytes is enough for ~85 short protos —
    /// well above any realistic client offer.
    alpn_protos: [256]u8 = .{0} ** 256,
    alpn_protos_len: usize = 0,
    /// True if the client sent the early_data extension (0-RTT request).
    has_early_data: bool = false,
    /// First PSK identity from pre_shared_key extension (ticket blob = PSK).
    psk_identity: [64]u8 = .{0} ** 64,
    psk_identity_len: usize = 0,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn readU16(b: []const u8) u16 {
    return std.mem.readInt(u16, b[0..2], .big);
}

fn readU24(b: []const u8) u32 {
    return (@as(u32, b[0]) << 16) | (@as(u32, b[1]) << 8) | @as(u32, b[2]);
}

fn writeU16(b: []u8, v: u16) void {
    std.mem.writeInt(u16, b[0..2], v, .big);
}

fn writeU24(b: []u8, v: u32) void {
    b[0] = @truncate(v >> 16);
    b[1] = @truncate(v >> 8);
    b[2] = @truncate(v);
}

/// Copy bytes into `out[pos..]`, return new pos.
fn put(out: []u8, pos: usize, data: []const u8) usize {
    @memcpy(out[pos .. pos + data.len], data);
    return pos + data.len;
}

/// Write a TLS handshake message header: type(1) + length(3).
fn writeHsMsgHeader(out: []u8, pos: usize, msg_type: u8, body_len: usize) usize {
    out[pos] = msg_type;
    writeU24(out[pos + 1 ..], @intCast(body_len));
    return pos + 4;
}

/// Peek the SHA-256 transcript hash without consuming the state.
pub fn peekHash(h: Sha256) [32]u8 {
    var copy = h;
    var out: [32]u8 = undefined;
    copy.final(&out);
    return out;
}

// ── TLS 1.3 key schedule ────────────────────────────────────────────────────

/// Derive one step of the TLS 1.3 key schedule: expand "derived" then extract.
fn deriveNextSecret(prev_secret: [32]u8, ikm: []const u8) [32]u8 {
    var empty_hash: [32]u8 = undefined;
    Sha256.hash("", &empty_hash, .{});
    var derived: [32]u8 = undefined;
    keys_mod.hkdfExpandLabel(&derived, &prev_secret, "derived", &empty_hash);
    return HkdfSha256.extract(&derived, ikm);
}

/// Derive a traffic secret: HKDF-Expand-Label(secret, label, hash, 32).
fn deriveTrafficSecret(secret: [32]u8, label: []const u8, hash: *const [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    keys_mod.hkdfExpandLabel(&out, &secret, label, hash);
    return out;
}

/// Derive the handshake_secret from the ECDHE shared key.
fn deriveHandshakeSecret(ecdhe_shared_key: [32]u8) [32]u8 {
    const zeroes = [_]u8{0} ** 32;
    const early_secret = HkdfSha256.extract(&[_]u8{0}, &zeroes);
    return deriveNextSecret(early_secret, &ecdhe_shared_key);
}

/// Derive the master_secret from handshake_secret.
fn deriveMasterSecret(hs_secret: [32]u8) [32]u8 {
    const zeroes = [_]u8{0} ** 32;
    return deriveNextSecret(hs_secret, &zeroes);
}

/// Compute the Finished verify_data: HMAC-SHA256(finished_key, transcript_hash).
fn computeFinishedVerifyData(traffic_secret: [32]u8, transcript_hash: *const [32]u8) [32]u8 {
    var finished_key: [32]u8 = undefined;
    keys_mod.hkdfExpandLabel(&finished_key, &traffic_secret, "finished", "");
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, transcript_hash, &finished_key);
    return mac;
}

// ── ClientHello parser ───────────────────────────────────────────────────────

pub const ParseError = error{
    TruncatedMessage,
    BadMessageType,
    BadVersion,
    UnsupportedCipherSuites,
    NoKeyShare,
};

/// Parse a raw ClientHello message (no record header).
/// The caller retains ownership of `data`; `result.quic_transport_params` holds
/// byte offsets into `data` if present.
pub fn parseClientHello(data: []const u8) ParseError!ClientHelloData {
    if (data.len < 4) return error.TruncatedMessage;
    if (data[0] != MSG_CLIENT_HELLO) return error.BadMessageType;

    const body_len = readU24(data[1..4]);
    if (data.len < 4 + body_len) return error.TruncatedMessage;
    const body = data[4 .. 4 + body_len];
    var p: usize = 0;

    // legacy_version (2)
    if (body.len < p + 2) return error.TruncatedMessage;
    p += 2;

    // random (32)
    if (body.len < p + 32) return error.TruncatedMessage;
    var result = ClientHelloData{};
    @memcpy(&result.random, body[p .. p + 32]);
    p += 32;

    // legacy_session_id
    if (body.len < p + 1) return error.TruncatedMessage;
    const sid_len = body[p];
    p += 1;
    if (sid_len > 32 or body.len < p + sid_len) return error.TruncatedMessage;
    result.session_id_len = sid_len;
    if (sid_len > 0) @memcpy(result.session_id[0..sid_len], body[p .. p + sid_len]);
    p += sid_len;

    // cipher_suites
    if (body.len < p + 2) return error.TruncatedMessage;
    const cs_len = readU16(body[p..]);
    p += 2;
    if (body.len < p + cs_len) return error.TruncatedMessage;
    result.cipher_suite = selectPreferredCipherSuite(body[p .. p + cs_len]) catch return error.UnsupportedCipherSuites;
    p += cs_len;

    // compression methods
    if (body.len < p + 1) return error.TruncatedMessage;
    const comp_len = body[p];
    p += 1 + comp_len;

    // extensions
    if (body.len < p + 2) return error.TruncatedMessage;
    const ext_total = readU16(body[p..]);
    p += 2;
    const ext_end = p + ext_total;
    if (body.len < ext_end) return error.TruncatedMessage;

    while (p + 4 <= ext_end) {
        const ext_type = readU16(body[p..]);
        const ext_len = readU16(body[p + 2 ..]);
        p += 4;
        if (p + ext_len > ext_end) break;
        const ext_data = body[p .. p + ext_len];

        switch (ext_type) {
            EXT_KEY_SHARE => {
                // key_share list: u16 total_len, then entries: u16 group, u16 key_len, key
                if (ext_data.len >= 2) {
                    const list_len = readU16(ext_data);
                    var kp: usize = 2;
                    while (kp + 4 <= 2 + list_len and kp + 4 <= ext_data.len) {
                        const group = readU16(ext_data[kp..]);
                        const klen = readU16(ext_data[kp + 2 ..]);
                        kp += 4;
                        if (kp + klen > ext_data.len) break;
                        if (group == GROUP_X25519 and klen == 32) {
                            result.x25519_key = ext_data[kp..][0..32].*;
                        }
                        kp += klen;
                    }
                }
            },
            EXT_SUPPORTED_GROUPS => {
                // Record whether the client lists X25519 among the groups it
                // supports, even if it did not send an X25519 *key_share*
                // (modern AWS-LC/BoringSSL lead their key_share with the
                // X25519MLKEM768 PQ hybrid and offer X25519 only here). This
                // drives the HelloRetryRequest decision in processClientHello.
                if (ext_data.len >= 2) {
                    const gl = readU16(ext_data);
                    var gp: usize = 2;
                    while (gp + 2 <= 2 + gl and gp + 2 <= ext_data.len) : (gp += 2) {
                        if (readU16(ext_data[gp..]) == GROUP_X25519) result.x25519_supported_group = true;
                    }
                }
            },
            EXT_QUIC_TRANSPORT_PARAMS, EXT_QUIC_TRANSPORT_PARAMS_DRAFT => {
                // Store offset into original data slice
                const offset = (data.ptr + 4 + @as(usize, @intCast(body_len - (body.len - p)))) - data.ptr;
                result.quic_transport_params = .{ .offset = offset, .len = ext_len };
                result.quic_transport_params_ext_type = ext_type;
            },
            EXT_ALPN => {
                // u16 list_len, then [u8 proto_len, proto]+
                if (ext_data.len >= 2) {
                    // Record the inner list (without the 2-byte length prefix)
                    // so [`eeAlpnMatchingClientOffer`] can match arbitrary
                    // preferred ALPN values, not just the two HTTP presets.
                    const inner = ext_data[2..];
                    const copy_len = @min(inner.len, result.alpn_protos.len);
                    @memcpy(result.alpn_protos[0..copy_len], inner[0..copy_len]);
                    result.alpn_protos_len = copy_len;

                    var ap: usize = 2;
                    while (ap + 1 <= ext_data.len) {
                        const plen = ext_data[ap];
                        ap += 1;
                        if (ap + plen > ext_data.len) break;
                        const proto = ext_data[ap .. ap + plen];
                        if (std.mem.eql(u8, proto, ALPN_H3)) result.alpn_h3 = true;
                        if (std.mem.eql(u8, proto, ALPN_H09)) result.alpn_h09 = true;
                        ap += plen;
                    }
                }
            },
            EXT_EARLY_DATA => {
                result.has_early_data = true;
            },
            EXT_PRE_SHARED_KEY => {
                // Extract first PSK identity: identities_len(2) + identity_len(2) + identity
                if (ext_data.len >= 4) {
                    const id_len = readU16(ext_data[2..]);
                    const ilen = @min(id_len, 64);
                    if (4 + ilen <= ext_data.len) {
                        @memcpy(result.psk_identity[0..ilen], ext_data[4 .. 4 + ilen]);
                        result.psk_identity_len = ilen;
                    }
                }
            },
            else => {},
        }
        p += ext_len;
    }

    // NOTE: a missing X25519 key_share is no longer a parse error — the caller
    // (processClientHello) decides between HelloRetryRequest (when X25519 is in
    // supported_groups) and rejection.
    return result;
}

/// Pick the best TLS 1.3 cipher from a ClientHello cipher_suites list (big-endian u16 values).
/// Prefer AES-128-GCM for QUIC interop: many peers (e.g. quinn) list AES-256 first but
/// expect the negotiated AEAD to match the suite (RFC 9001 §5.3).
pub fn selectPreferredCipherSuite(cs_list: []const u8) !u16 {
    var best: u16 = 0;
    var best_rank: u8 = 0;
    var i: usize = 0;
    while (i + 1 < cs_list.len) : (i += 2) {
        const cs = readU16(cs_list[i..]);
        const rank: u8 = switch (cs) {
            TLS_AES_128_GCM_SHA256 => 3,
            TLS_CHACHA20_POLY1305_SHA256 => 2,
            TLS_AES_256_GCM_SHA384 => 1,
            else => 0,
        };
        if (rank > best_rank) {
            best_rank = rank;
            best = cs;
        }
    }
    if (best_rank == 0) return error.UnsupportedCipherSuites;
    return best;
}

// ── ServerHello builder ──────────────────────────────────────────────────────

/// Build a TLS 1.3 ServerHello message (raw, no record header).
/// Returns bytes written to `out`.
pub fn buildServerHello(
    out: []u8,
    session_id: []const u8,
    cipher_suite: u16,
    server_x25519_pub: *const [32]u8,
    accept_psk: bool,
) !usize {
    // Body: version(2) + random(32) + sid_len(1) + sid + cs(2) + comp(1) + exts
    const server_random = blk: {
        var r: [32]u8 = undefined;
        compat.random.bytes(&r);
        break :blk r;
    };

    // Build extensions:
    //   supported_versions: type(2)+len(2)+data(2) = 6 bytes
    //   key_share: type(2)+len(2)+group(2)+key_len(2)+key(32) = 40 bytes
    //   pre_shared_key (optional): type(2)+len(2)+selected_identity(2) = 6 bytes
    var ext_buf: [128]u8 = undefined;
    var ep: usize = 0;
    // supported_versions
    writeU16(ext_buf[ep..], EXT_SUPPORTED_VERSIONS);
    ep += 2;
    writeU16(ext_buf[ep..], 2); // ext data length = 2
    ep += 2;
    writeU16(ext_buf[ep..], TLS_VERSION_13);
    ep += 2;
    // key_share: group(2) + key_len(2) + key(32) = 36 bytes of data
    writeU16(ext_buf[ep..], EXT_KEY_SHARE);
    ep += 2;
    writeU16(ext_buf[ep..], 36); // ext data length
    ep += 2;
    writeU16(ext_buf[ep..], GROUP_X25519);
    ep += 2;
    writeU16(ext_buf[ep..], 32);
    ep += 2;
    @memcpy(ext_buf[ep .. ep + 32], server_x25519_pub);
    ep += 32;
    // pre_shared_key: selected_identity = 0 (RFC 8446 §4.2.11)
    if (accept_psk) {
        writeU16(ext_buf[ep..], EXT_PRE_SHARED_KEY);
        ep += 2;
        writeU16(ext_buf[ep..], 2); // ext data length = 2
        ep += 2;
        writeU16(ext_buf[ep..], 0); // selected_identity = 0
        ep += 2;
    }

    const body_len = 2 + 32 + 1 + session_id.len + 2 + 1 + 2 + ep;
    if (out.len < 4 + body_len) return error.BufferTooSmall;

    var pos: usize = writeHsMsgHeader(out, 0, MSG_SERVER_HELLO, body_len);
    // legacy_version = 0x0303
    writeU16(out[pos..], TLS_LEGACY_VERSION);
    pos += 2;
    // random
    @memcpy(out[pos .. pos + 32], &server_random);
    pos += 32;
    // session_id
    out[pos] = @intCast(session_id.len);
    pos += 1;
    if (session_id.len > 0) {
        @memcpy(out[pos .. pos + session_id.len], session_id);
        pos += session_id.len;
    }
    // cipher_suite
    writeU16(out[pos..], cipher_suite);
    pos += 2;
    // compression = 0
    out[pos] = 0;
    pos += 1;
    // extensions length
    writeU16(out[pos..], @intCast(ep));
    pos += 2;
    @memcpy(out[pos .. pos + ep], ext_buf[0..ep]);
    pos += ep;

    return pos;
}

/// SHA-256("HelloRetryRequest") — the special ServerHello.random that marks a
/// message as a HelloRetryRequest (RFC 8446 §4.1.3).
pub const hello_retry_request_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// Build a HelloRetryRequest (RFC 8446 §4.1.4): a ServerHello carrying the HRR
/// magic random, echoing the client's session_id + chosen cipher suite, plus a
/// key_share extension that names ONLY the `group` the server wants the client
/// to use on its next ClientHello (no key bytes). Sent when the ClientHello
/// carried no key_share for a group we support (e.g. modern AWS-LC/BoringSSL
/// lead with X25519MLKEM768) but listed one we do (X25519) in supported_groups.
pub fn buildHelloRetryRequest(
    out: []u8,
    session_id: []const u8,
    cipher_suite: u16,
    group: u16,
) !usize {
    var ext_buf: [64]u8 = undefined;
    var ep: usize = 0;
    // supported_versions: selected_version = TLS 1.3
    writeU16(ext_buf[ep..], EXT_SUPPORTED_VERSIONS);
    ep += 2;
    writeU16(ext_buf[ep..], 2);
    ep += 2;
    writeU16(ext_buf[ep..], TLS_VERSION_13);
    ep += 2;
    // key_share (HRR form): ext data = selected_group only (2 bytes), no key.
    writeU16(ext_buf[ep..], EXT_KEY_SHARE);
    ep += 2;
    writeU16(ext_buf[ep..], 2);
    ep += 2;
    writeU16(ext_buf[ep..], group);
    ep += 2;

    const body_len = 2 + 32 + 1 + session_id.len + 2 + 1 + 2 + ep;
    if (out.len < 4 + body_len) return error.BufferTooSmall;

    var pos: usize = writeHsMsgHeader(out, 0, MSG_SERVER_HELLO, body_len);
    writeU16(out[pos..], TLS_LEGACY_VERSION);
    pos += 2;
    @memcpy(out[pos .. pos + 32], &hello_retry_request_random);
    pos += 32;
    out[pos] = @intCast(session_id.len);
    pos += 1;
    if (session_id.len > 0) {
        @memcpy(out[pos .. pos + session_id.len], session_id);
        pos += session_id.len;
    }
    writeU16(out[pos..], cipher_suite);
    pos += 2;
    out[pos] = 0; // compression
    pos += 1;
    writeU16(out[pos..], @intCast(ep));
    pos += 2;
    @memcpy(out[pos .. pos + ep], ext_buf[0..ep]);
    pos += ep;
    return pos;
}

/// Locate the `quic_transport_parameters` TLS extension body inside a complete
/// `EncryptedExtensions` handshake message (including its 4-byte handshake
/// header). Returns null on any malformation rather than erroring — the caller
/// treats absence as "fall back to RFC defaults".
pub fn extractQuicTpFromEncryptedExtensions(msg: []const u8) ?[]const u8 {
    // Handshake message header: msg_type(1) + length(3).
    if (msg.len < 4) return null;
    if (msg[0] != MSG_ENCRYPTED_EXTENSIONS) return null;
    const body_len = readU24(msg[1..]);
    if (4 + body_len > msg.len) return null;
    const body = msg[4 .. 4 + body_len];
    // EncryptedExtensions body: extensions<6..2^16-1> (2-byte length prefix).
    if (body.len < 2) return null;
    const ext_total = (@as(usize, body[0]) << 8) | body[1];
    if (2 + ext_total > body.len) return null;
    var p: usize = 2;
    const end = 2 + ext_total;
    while (p + 4 <= end) {
        const ext_type = (@as(u16, body[p]) << 8) | body[p + 1];
        const ext_len = (@as(usize, body[p + 2]) << 8) | body[p + 3];
        p += 4;
        if (p + ext_len > end) return null;
        if (isQuicTransportParamsExt(ext_type)) {
            return body[p .. p + ext_len];
        }
        p += ext_len;
    }
    return null;
}

// ── EncryptedExtensions builder ───────────────────────────────────────────────

/// Build a TLS 1.3 EncryptedExtensions message (raw, no record header).
/// When `accept_early_data` is true, includes the early_data extension (0x002a)
/// to signal that the server accepts 0-RTT data.
pub fn buildEncryptedExtensions(
    out: []u8,
    quic_transport_params: []const u8,
    tp_ext_type: u16,
    alpn: ?[]const u8,
    accept_early_data: bool,
) !usize {
    // Extensions content
    var ext_buf: [2048]u8 = undefined;
    var ep: usize = 0;

    // QUIC transport parameters extension — echo the type the peer offered (RFC 9001 §8.2).
    writeU16(ext_buf[ep..], tp_ext_type);
    ep += 2;
    writeU16(ext_buf[ep..], @intCast(quic_transport_params.len));
    ep += 2;
    @memcpy(ext_buf[ep .. ep + quic_transport_params.len], quic_transport_params);
    ep += quic_transport_params.len;

    // ALPN extension (if provided)
    if (alpn) |a| {
        writeU16(ext_buf[ep..], EXT_ALPN);
        ep += 2;
        // ext_data = u16_list_len(2) + u8_proto_len(1) + proto
        const ext_data_len: u16 = @intCast(2 + 1 + a.len);
        writeU16(ext_buf[ep..], ext_data_len);
        ep += 2;
        writeU16(ext_buf[ep..], @intCast(1 + a.len)); // list len
        ep += 2;
        ext_buf[ep] = @intCast(a.len);
        ep += 1;
        @memcpy(ext_buf[ep .. ep + a.len], a);
        ep += a.len;
    }

    // early_data acceptance (signals server accepts 0-RTT)
    if (accept_early_data) {
        writeU16(ext_buf[ep..], EXT_EARLY_DATA);
        ep += 2;
        writeU16(ext_buf[ep..], 0); // empty body
        ep += 2;
    }

    // Body = u16 ext list len + ext list
    const body_len = 2 + ep;
    if (out.len < 4 + body_len) return error.BufferTooSmall;

    var pos: usize = writeHsMsgHeader(out, 0, MSG_ENCRYPTED_EXTENSIONS, body_len);
    writeU16(out[pos..], @intCast(ep));
    pos += 2;
    @memcpy(out[pos .. pos + ep], ext_buf[0..ep]);
    pos += ep;
    return pos;
}

/// ALPN for EncryptedExtensions only when the client offered it (rustls
/// `server/hs.rs` `process_common` + client `validate_encrypted_extensions`).
///
/// Scans `ch.alpn_protos[0..alpn_protos_len]` — the captured client
/// ProtocolNameList inner bytes — for an exact match against the
/// server's preferred ALPN. This is what lets us echo arbitrary
/// preset strings like `libp2p` (the libp2p QUIC interop ALPN, RFC 9000)
/// without limiting the matcher to HTTP presets.
fn eeAlpnMatchingClientOffer(ch: *const ClientHelloData, preferred: ?[]const u8) ?[]const u8 {
    const p = preferred orelse return null;
    // Fast-path keeps the existing HTTP cases trivial.
    if (std.mem.eql(u8, p, ALPN_H3) and ch.alpn_h3) return p;
    if (std.mem.eql(u8, p, ALPN_H09) and ch.alpn_h09) return p;
    // General case: walk the captured offer list.
    var ap: usize = 0;
    while (ap + 1 <= ch.alpn_protos_len) {
        const plen = ch.alpn_protos[ap];
        ap += 1;
        if (ap + plen > ch.alpn_protos_len) break;
        const proto = ch.alpn_protos[ap .. ap + plen];
        if (std.mem.eql(u8, proto, p)) return p;
        ap += plen;
    }
    return null;
}

/// early_data in EE only on accepted PSK resumption (rustls `decide_if_early_data_allowed`).
fn eeAcceptEarlyData(ch: *const ClientHelloData, accept_psk: bool) bool {
    return ch.has_early_data and accept_psk;
}

/// Pick EE ALPN from server preference and client offers (quinn interop uses hq-interop).
fn negotiateEeAlpn(ch: *const ClientHelloData, preferred: ?[]const u8) ?[]const u8 {
    if (eeAlpnMatchingClientOffer(ch, preferred)) |a| return a;
    if (ch.alpn_h09) return ALPN_H09;
    return null;
}

/// RFC 8446 §4.2.9: advertise PSK with (EC)DHE key establishment.
fn appendClientHelloPskKeyExchangeModes(ext_buf: []u8, ep: usize) usize {
    var p = ep;
    writeU16(ext_buf[p..], EXT_PSK_KEY_EXCHANGE_MODES);
    p += 2;
    writeU16(ext_buf[p..], 2); // ext data: list_len(1) + mode(1)
    p += 2;
    ext_buf[p] = 1; // list len
    p += 1;
    ext_buf[p] = 1; // psk_dhe_ke
    p += 1;
    return p;
}

/// RFC 8446 §4.2.3: TLS 1.3 ClientHello MUST include signature_algorithms.
fn appendClientHelloSignatureAlgorithms(ext_buf: []u8, ep: usize) usize {
    var p = ep;
    writeU16(ext_buf[p..], EXT_SIGNATURE_ALGORITHMS);
    p += 2;
    writeU16(ext_buf[p..], 8); // ext data: list_len(2) + 3× u16 schemes
    p += 2;
    writeU16(ext_buf[p..], 6); // signature list length in bytes
    p += 2;
    writeU16(ext_buf[p..], SIG_ECDSA_SECP256R1_SHA256);
    p += 2;
    writeU16(ext_buf[p..], SIG_ECDSA_SECP384R1_SHA384);
    p += 2;
    writeU16(ext_buf[p..], SIG_RSA_PSS_RSAE_SHA256);
    p += 2;
    return p;
}

// ── Certificate builder ───────────────────────────────────────────────────────

/// Build a TLS 1.3 Certificate message with one DER certificate.
pub fn buildCertificate(out: []u8, cert_der: []const u8) !usize {
    // cert_list entry: u24 cert_data_len + cert_data + u16 extensions_len(0)
    const entry_len = 3 + cert_der.len + 2;
    // cert_list total length
    const list_len = entry_len;
    // body: request_context(1) + u24 cert_list_len + cert_list
    const body_len = 1 + 3 + list_len;
    if (out.len < 4 + body_len) return error.BufferTooSmall;

    var pos: usize = writeHsMsgHeader(out, 0, MSG_CERTIFICATE, body_len);
    // request_context = empty
    out[pos] = 0;
    pos += 1;
    // cert_list length
    writeU24(out[pos..], @intCast(list_len));
    pos += 3;
    // cert data length
    writeU24(out[pos..], @intCast(cert_der.len));
    pos += 3;
    // cert data
    @memcpy(out[pos .. pos + cert_der.len], cert_der);
    pos += cert_der.len;
    // extensions for this cert entry = empty
    writeU16(out[pos..], 0);
    pos += 2;
    return pos;
}

fn readTlsHandshakeU24Cert(buf: []const u8, pos: usize) error{MalformedCertificate}!struct { v: u32, next: usize } {
    if (pos + 3 > buf.len) return error.MalformedCertificate;
    const v = (@as(u32, buf[pos]) << 16) | (@as(u32, buf[pos + 1]) << 8) | @as(u32, buf[pos + 2]);
    return .{ .v = v, .next = pos + 3 };
}

/// First certificate entry DER from a TLS 1.3 `Certificate` handshake message (type `0x0b`), or
/// `null` when the certificate list is empty (anonymous client after `CertificateRequest`).
/// `message` is the full message: type (1) + length (3) + body.
pub fn leafCertificateDerFromCertificateHandshakeMessageOptional(message: []const u8) error{MalformedCertificate}!?[]const u8 {
    if (message.len < 4) return error.MalformedCertificate;
    if (message[0] != MSG_CERTIFICATE) return error.MalformedCertificate;
    const lh = try readTlsHandshakeU24Cert(message, 1);
    const body_end = lh.next + lh.v;
    if (body_end > message.len) return error.MalformedCertificate;
    const body = message[lh.next..body_end];
    if (body.len < 1) return error.MalformedCertificate;
    const ctx_len = body[0];
    const after_ctx = 1 + ctx_len;
    if (after_ctx > body.len) return error.MalformedCertificate;
    const list_h = try readTlsHandshakeU24Cert(body, after_ctx);
    const list_end = list_h.next + list_h.v;
    if (list_end > body.len) return error.MalformedCertificate;
    const list = body[list_h.next..list_end];
    if (list.len == 0) return null;
    if (list.len < 3) return error.MalformedCertificate;
    const cert_len_h = try readTlsHandshakeU24Cert(list, 0);
    const cert_end = cert_len_h.next + cert_len_h.v;
    if (cert_end > list.len) return error.MalformedCertificate;
    return list[cert_len_h.next..cert_end];
}

/// First certificate entry DER from a TLS 1.3 `Certificate` handshake message (type `0x0b`).
/// `message` is the full message: type (1) + length (3) + body.
pub fn leafCertificateDerFromCertificateHandshakeMessage(message: []const u8) error{MalformedCertificate}![]const u8 {
    return (try leafCertificateDerFromCertificateHandshakeMessageOptional(message)) orelse error.MalformedCertificate;
}

/// TLS 1.3 `CertificateRequest` with `signature_algorithms` (ECDSA P-256 / P-384), matching
/// [`buildClientCertificateVerify`] schemes supported by this stack.
pub fn buildCertificateRequest(out: []u8) !usize {
    var ext_buf: [16]u8 = undefined;
    var ep: usize = 0;
    writeU16(ext_buf[ep..], EXT_SIGNATURE_ALGORITHMS);
    ep += 2;
    // extension_data = SignatureSchemeList: u16 list_len + schemes (same layout as
    // appendClientHelloSignatureAlgorithms — omitting list_len breaks go/crypto/tls).
    writeU16(ext_buf[ep..], 6); // ext data: list_len(2) + 2× u16 schemes
    ep += 2;
    writeU16(ext_buf[ep..], 4); // signature list length in bytes
    ep += 2;
    writeU16(ext_buf[ep..], SIG_ECDSA_SECP256R1_SHA256);
    ep += 2;
    writeU16(ext_buf[ep..], SIG_ECDSA_SECP384R1_SHA384);
    ep += 2;

    const body_len = 1 + 2 + ep;
    if (out.len < 4 + body_len) return error.BufferTooSmall;

    var pos: usize = writeHsMsgHeader(out, 0, MSG_CERTIFICATE_REQUEST, body_len);
    out[pos] = 0;
    pos += 1;
    writeU16(out[pos..], @intCast(ep));
    pos += 2;
    @memcpy(out[pos..][0..ep], ext_buf[0..ep]);
    pos += ep;
    return pos;
}

/// TLS 1.3 `Certificate` handshake message with an empty certificate list (client has no cert).
pub fn buildEmptyCertificate(out: []u8) !usize {
    const body_len = 1 + 3;
    if (out.len < 4 + body_len) return error.BufferTooSmall;
    var pos: usize = writeHsMsgHeader(out, 0, MSG_CERTIFICATE, body_len);
    out[pos] = 0;
    pos += 1;
    writeU24(out[pos..], 0);
    pos += 3;
    return pos;
}

// ── CertificateVerify builder ─────────────────────────────────────────────────

/// TLS 1.3 CertificateVerify content prefix: 64 spaces + context string + 0x00.
const CV_PREFIX_SERVER = " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00";
const CV_PREFIX_CLIENT = " " ** 64 ++ "TLS 1.3, client CertificateVerify\x00";

/// Build a TLS 1.3 CertificateVerify using the server's private key.
/// `transcript_hash` is the SHA-256 of all messages through Certificate.
pub fn buildCertificateVerify(
    out: []u8,
    transcript_hash: *const [32]u8,
    private_key: *const tls_vendor.config.PrivateKey,
) !usize {
    return buildCertificateVerifyWithContext(out, transcript_hash, private_key, CV_PREFIX_SERVER);
}

/// Same as [`buildCertificateVerify`] but uses the client CertificateVerify transcript prefix (RFC 8446 §4.4.3).
pub fn buildClientCertificateVerify(
    out: []u8,
    transcript_hash: *const [32]u8,
    private_key: *const tls_vendor.config.PrivateKey,
) !usize {
    return buildCertificateVerifyWithContext(out, transcript_hash, private_key, CV_PREFIX_CLIENT);
}

fn buildCertificateVerifyWithContext(
    out: []u8,
    transcript_hash: *const [32]u8,
    private_key: *const tls_vendor.config.PrivateKey,
    context_prefix: []const u8,
) !usize {
    comptime {
        std.debug.assert(CV_PREFIX_SERVER.len == CV_PREFIX_CLIENT.len);
    }
    std.debug.assert(context_prefix.len == CV_PREFIX_SERVER.len);

    // Content to sign
    var to_sign: [64 + 34 + 32]u8 = undefined;
    _ = put(&to_sign, 0, context_prefix);
    @memcpy(to_sign[context_prefix.len..][0..32], transcript_hash);

    // sig_der_buf is 104 bytes — max DER size for P-384 (P-256 is 72).
    var sig_der_buf: [104]u8 = undefined;
    var sig_der_len: usize = 0;
    const sig_scheme = @intFromEnum(private_key.signature_scheme);
    switch (private_key.signature_scheme) {
        .ecdsa_secp256r1_sha256 => {
            const sk = try EcdsaP256Sha256.SecretKey.fromBytes(private_key.key.ecdsa[0..32].*);
            const kp = try EcdsaP256Sha256.KeyPair.fromSecretKey(sk);
            var signer = try kp.signer(null);
            signer.update(&to_sign);
            const sig = try signer.finalize();
            var p256_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
            const der = sig.toDer(&p256_buf);
            @memcpy(sig_der_buf[0..der.len], der);
            sig_der_len = der.len;
        },
        .ecdsa_secp384r1_sha384 => {
            const sk = try EcdsaP384Sha384.SecretKey.fromBytes(private_key.key.ecdsa[0..48].*);
            const kp = try EcdsaP384Sha384.KeyPair.fromSecretKey(sk);
            var signer = try kp.signer(null);
            signer.update(&to_sign);
            const sig = try signer.finalize();
            var p384_buf: [EcdsaP384Sha384.Signature.der_encoded_length_max]u8 = undefined;
            const der = sig.toDer(&p384_buf);
            @memcpy(sig_der_buf[0..der.len], der);
            sig_der_len = der.len;
        },
        else => return error.UnsupportedSignatureScheme,
    }
    const sig_bytes = sig_der_buf[0..sig_der_len];

    // CertificateVerify body: sig_scheme(2) + sig_len(2) + sig
    const body_len = 2 + 2 + sig_bytes.len;
    if (out.len < 4 + body_len) return error.BufferTooSmall;

    var pos: usize = writeHsMsgHeader(out, 0, MSG_CERTIFICATE_VERIFY, body_len);
    writeU16(out[pos..], sig_scheme);
    pos += 2;
    writeU16(out[pos..], @intCast(sig_bytes.len));
    pos += 2;
    @memcpy(out[pos .. pos + sig_bytes.len], sig_bytes);
    pos += sig_bytes.len;
    return pos;
}

/// Verify a TLS 1.3 client `CertificateVerify` handshake message using the leaf SPKI from the preceding `Certificate` message.
pub fn verifyClientCertificateVerifyMessage(
    msg: []const u8,
    leaf_der: []const u8,
    transcript_hash: *const [32]u8,
) !void {
    if (msg.len < 4) return error.TruncatedMessage;
    if (msg[0] != MSG_CERTIFICATE_VERIFY) return error.BadMessageType;
    const body_len = readU24(msg[1..4]);
    if (4 + body_len > msg.len) return error.TruncatedMessage;
    const body = msg[4 .. 4 + body_len];
    if (body.len < 4) return error.TruncatedMessage;
    const sig_scheme = readU16(body);
    const sig_len = readU16(body[2..]);
    if (4 + sig_len > body.len) return error.TruncatedMessage;
    const sig_der = body[4 .. 4 + sig_len];

    var to_sign: [64 + 34 + 32]u8 = undefined;
    _ = put(&to_sign, 0, CV_PREFIX_CLIENT);
    @memcpy(to_sign[CV_PREFIX_CLIENT.len..][0..32], transcript_hash);

    const parsed = try (Certificate{ .buffer = leaf_der, .index = 0 }).parse();
    const spki = parsed.pubKey();

    switch (sig_scheme) {
        SIG_ECDSA_SECP256R1_SHA256 => {
            const pk = try EcdsaP256Sha256.PublicKey.fromSec1(spki);
            const sig = try EcdsaP256Sha256.Signature.fromDer(sig_der);
            try sig.verify(&to_sign, pk);
        },
        SIG_ECDSA_SECP384R1_SHA384 => {
            const pk = try EcdsaP384Sha384.PublicKey.fromSec1(spki);
            const sig = try EcdsaP384Sha384.Signature.fromDer(sig_der);
            try sig.verify(&to_sign, pk);
        },
        else => return error.UnsupportedSignatureScheme,
    }
}

// ── Finished builder ─────────────────────────────────────────────────────────

/// Build a TLS 1.3 Finished message.
pub fn buildFinished(
    out: []u8,
    traffic_secret: [32]u8,
    transcript_hash: *const [32]u8,
) usize {
    const verify_data = computeFinishedVerifyData(traffic_secret, transcript_hash);
    const pos: usize = writeHsMsgHeader(out, 0, MSG_FINISHED, 32);
    @memcpy(out[pos .. pos + 32], &verify_data);
    return pos + 32;
}

// ── ClientHello builder ───────────────────────────────────────────────────────

/// Build a TLS 1.3 ClientHello message for QUIC.
pub fn buildClientHello(
    out: []u8,
    client_x25519_pub: *const [32]u8,
    quic_transport_params: []const u8,
    alpn: ?[]const u8,
    server_name: ?[]const u8,
) !usize {
    return buildClientHelloInner(out, client_x25519_pub, quic_transport_params, alpn, server_name, false);
}

// ── PSK / session resumption ──────────────────────────────────────────────────

/// PSK information for TLS 1.3 session resumption ClientHello.
pub const PskInfo = struct {
    /// Opaque ticket blob from the server's NewSessionTicket message.
    ticket: []const u8,
    /// Obfuscated ticket age (actual_age_ms + ticket_age_add) mod 2^32.
    /// Use 0 when ticket_age_add is not tracked (RFC 8446 §4.2.11.1).
    obfuscated_age: u32,
    /// PSK (resumption_secret from the previous session).
    psk: [32]u8,
};

/// Compute the PSK binder for TLS 1.3 session resumption (RFC 8446 §4.2.11.2).
///
/// `partial_ch` = all ClientHello bytes up to and including the PSK
/// identities section (NOT including the binders_len/binders fields).
fn computeResumptionBinder(psk: [32]u8, partial_ch: []const u8) [32]u8 {
    // SHA-256("") — empty transcript hash constant.
    const empty_hash = [32]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    // early_secret = HKDF-Extract(salt=zeros_32, IKM=PSK)
    const zeros: [32]u8 = .{0} ** 32;
    const early_secret = HkdfSha256.extract(&zeros, &psk);
    // binder_key = HKDF-Expand-Label(early_secret, "res binder", SHA-256(""), 32)
    var binder_key: [32]u8 = undefined;
    keys_mod.hkdfExpandLabel(&binder_key, &early_secret, "res binder", &empty_hash);
    // finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
    var finished_key: [32]u8 = undefined;
    keys_mod.hkdfExpandLabel(&finished_key, &binder_key, "finished", "");
    // binder = HMAC-SHA256(finished_key, SHA-256(partial_ch))
    var partial_hash: [32]u8 = undefined;
    Sha256.hash(partial_ch, &partial_hash, .{});
    var binder: [32]u8 = undefined;
    HmacSha256.create(&binder, &partial_hash, &finished_key);
    return binder;
}

/// Build a TLS 1.3 ClientHello with a pre_shared_key extension for session
/// resumption (RFC 8446 §4.2.11).  The pre_shared_key extension is always the
/// last extension, and a psk_key_exchange_modes extension (psk_dhe_ke) is
/// inserted immediately before it.
///
/// The PSK binder is computed and written into the message before returning.
pub fn buildClientHelloWithPsk(
    out: []u8,
    client_x25519_pub: *const [32]u8,
    quic_transport_params: []const u8,
    alpn: ?[]const u8,
    server_name: ?[]const u8,
    psk_info: PskInfo,
    prefer_chacha20: bool,
    include_early_data: bool,
) !usize {
    var client_random: [32]u8 = undefined;
    compat.random.bytes(&client_random);

    // Build all extensions except pre_shared_key into ext_buf.
    var ext_buf: [2048]u8 = undefined;
    var ep: usize = 0;

    if (server_name) |sn| {
        writeU16(ext_buf[ep..], EXT_SERVER_NAME);
        ep += 2;
        const sni_data_len: u16 = @intCast(2 + 1 + 2 + sn.len);
        writeU16(ext_buf[ep..], sni_data_len);
        ep += 2;
        writeU16(ext_buf[ep..], @intCast(1 + 2 + sn.len));
        ep += 2;
        ext_buf[ep] = 0; // host_name type
        ep += 1;
        writeU16(ext_buf[ep..], @intCast(sn.len));
        ep += 2;
        @memcpy(ext_buf[ep .. ep + sn.len], sn);
        ep += sn.len;
    }
    writeU16(ext_buf[ep..], EXT_SUPPORTED_VERSIONS);
    ep += 2;
    writeU16(ext_buf[ep..], 3);
    ep += 2;
    ext_buf[ep] = 2;
    ep += 1;
    writeU16(ext_buf[ep..], TLS_VERSION_13);
    ep += 2;

    ep = appendClientHelloSignatureAlgorithms(ext_buf[0..], ep);

    // supported_groups: X25519 + secp256r1 (see buildClientHelloInner for rationale).
    writeU16(ext_buf[ep..], EXT_SUPPORTED_GROUPS);
    ep += 2;
    writeU16(ext_buf[ep..], 6);
    ep += 2;
    writeU16(ext_buf[ep..], 4);
    ep += 2;
    writeU16(ext_buf[ep..], GROUP_X25519);
    ep += 2;
    writeU16(ext_buf[ep..], GROUP_SECP256R1);
    ep += 2;

    writeU16(ext_buf[ep..], EXT_KEY_SHARE);
    ep += 2;
    writeU16(ext_buf[ep..], 38);
    ep += 2;
    writeU16(ext_buf[ep..], 36);
    ep += 2;
    writeU16(ext_buf[ep..], GROUP_X25519);
    ep += 2;
    writeU16(ext_buf[ep..], 32);
    ep += 2;
    @memcpy(ext_buf[ep .. ep + 32], client_x25519_pub);
    ep += 32;

    writeU16(ext_buf[ep..], EXT_QUIC_TRANSPORT_PARAMS);
    ep += 2;
    writeU16(ext_buf[ep..], @intCast(quic_transport_params.len));
    ep += 2;
    @memcpy(ext_buf[ep .. ep + quic_transport_params.len], quic_transport_params);
    ep += quic_transport_params.len;

    if (alpn) |a| {
        writeU16(ext_buf[ep..], EXT_ALPN);
        ep += 2;
        const adata_len: u16 = @intCast(2 + 1 + a.len);
        writeU16(ext_buf[ep..], adata_len);
        ep += 2;
        writeU16(ext_buf[ep..], @intCast(1 + a.len));
        ep += 2;
        ext_buf[ep] = @intCast(a.len);
        ep += 1;
        @memcpy(ext_buf[ep .. ep + a.len], a);
        ep += a.len;
    }

    // early_data extension (0x002a) — signals 0-RTT support, placed before psk_key_exchange_modes.
    if (include_early_data) {
        writeU16(ext_buf[ep..], EXT_EARLY_DATA);
        ep += 2;
        writeU16(ext_buf[ep..], 0); // empty body
        ep += 2;
    }

    // psk_key_exchange_modes — MUST appear before pre_shared_key.
    writeU16(ext_buf[ep..], EXT_PSK_KEY_EXCHANGE_MODES);
    ep += 2;
    writeU16(ext_buf[ep..], 2); // ext_data_len = modes_len(1) + mode(1)
    ep += 2;
    ext_buf[ep] = 1; // ke_modes list length
    ep += 1;
    ext_buf[ep] = 1; // psk_dhe_ke = 1
    ep += 1;

    // PSK extension layout (appended after ext_buf, last in CH):
    //   type(2) + ext_data_len(2)
    //   + identities_len(2) + identity_len(2) + ticket(N) + age(4)
    //   + binders_len(2) + binder_entry_len(1) + binder(32)
    const ticket = psk_info.ticket;
    const id_list_len: usize = 2 + ticket.len + 4;
    const binder_list_len: usize = 1 + 32;
    const psk_ext_data_len: usize = 2 + id_list_len + 2 + binder_list_len;
    const psk_ext_total: usize = 4 + psk_ext_data_len;
    const total_ext_len: usize = ep + psk_ext_total;

    const cs_data_len: usize = if (prefer_chacha20) 4 else 2;
    // body = version(2) + random(32) + sid_len(1) + cs_len(2) + cs + comp_len(1) + comp(1) + exts_len(2) + exts
    const body_len = 2 + 32 + 1 + (2 + cs_data_len) + 2 + 2 + total_ext_len;
    if (out.len < 4 + body_len) return error.BufferTooSmall;

    var pos: usize = writeHsMsgHeader(out, 0, MSG_CLIENT_HELLO, body_len);
    writeU16(out[pos..], TLS_LEGACY_VERSION);
    pos += 2;
    @memcpy(out[pos .. pos + 32], &client_random);
    pos += 32;
    out[pos] = 0; // session_id = empty
    pos += 1;
    writeU16(out[pos..], @intCast(cs_data_len));
    pos += 2;
    if (prefer_chacha20) {
        writeU16(out[pos..], TLS_CHACHA20_POLY1305_SHA256);
        pos += 2;
        writeU16(out[pos..], TLS_AES_128_GCM_SHA256);
        pos += 2;
    } else {
        writeU16(out[pos..], TLS_AES_128_GCM_SHA256);
        pos += 2;
    }
    out[pos] = 1; // compression methods count
    pos += 1;
    out[pos] = 0; // no compression
    pos += 1;
    writeU16(out[pos..], @intCast(total_ext_len));
    pos += 2;
    // Regular extensions
    @memcpy(out[pos .. pos + ep], ext_buf[0..ep]);
    pos += ep;

    // PSK extension — MUST be last.
    writeU16(out[pos..], EXT_PRE_SHARED_KEY);
    pos += 2;
    writeU16(out[pos..], @intCast(psk_ext_data_len));
    pos += 2;
    // identities
    writeU16(out[pos..], @intCast(id_list_len));
    pos += 2;
    writeU16(out[pos..], @intCast(ticket.len));
    pos += 2;
    @memcpy(out[pos .. pos + ticket.len], ticket);
    pos += ticket.len;
    std.mem.writeInt(u32, out[pos..][0..4], psk_info.obfuscated_age, .big);
    pos += 4;
    // ← partial_ch boundary (everything above is hashed for binder computation)
    const partial_ch_end = pos;

    // binders
    writeU16(out[pos..], @intCast(binder_list_len));
    pos += 2;
    out[pos] = 32; // binder entry byte length
    pos += 1;
    const binder_pos = pos;
    @memset(out[pos .. pos + 32], 0); // placeholder — filled in below
    pos += 32;

    // Compute and fill in the binder.
    const binder = computeResumptionBinder(psk_info.psk, out[0..partial_ch_end]);
    @memcpy(out[binder_pos .. binder_pos + 32], &binder);

    return pos;
}

/// Build a ClientHello that advertises ChaCha20-Poly1305 as the preferred
/// cipher suite, followed by AES-128-GCM as fallback.
pub fn buildClientHelloChaCha20(
    out: []u8,
    client_x25519_pub: *const [32]u8,
    quic_transport_params: []const u8,
    alpn: ?[]const u8,
    server_name: ?[]const u8,
) !usize {
    return buildClientHelloInner(out, client_x25519_pub, quic_transport_params, alpn, server_name, true);
}

fn buildClientHelloInner(
    out: []u8,
    client_x25519_pub: *const [32]u8,
    quic_transport_params: []const u8,
    alpn: ?[]const u8,
    server_name: ?[]const u8,
    prefer_chacha20: bool,
) !usize {
    var client_random: [32]u8 = undefined;
    compat.random.bytes(&client_random);

    // Build extensions
    var ext_buf: [2048]u8 = undefined;
    var ep: usize = 0;

    // server_name (SNI) extension if provided
    if (server_name) |sn| {
        writeU16(ext_buf[ep..], EXT_SERVER_NAME);
        ep += 2;
        const sni_data_len: u16 = @intCast(2 + 1 + 2 + sn.len);
        writeU16(ext_buf[ep..], sni_data_len);
        ep += 2;
        writeU16(ext_buf[ep..], @intCast(1 + 2 + sn.len)); // list len
        ep += 2;
        ext_buf[ep] = 0; // host_name type
        ep += 1;
        writeU16(ext_buf[ep..], @intCast(sn.len));
        ep += 2;
        @memcpy(ext_buf[ep .. ep + sn.len], sn);
        ep += sn.len;
    }

    // supported_versions: just TLS 1.3
    writeU16(ext_buf[ep..], EXT_SUPPORTED_VERSIONS);
    ep += 2;
    writeU16(ext_buf[ep..], 3); // ext data len: 1 (list_len) + 2 (version)
    ep += 2;
    ext_buf[ep] = 2; // list byte len
    ep += 1;
    writeU16(ext_buf[ep..], TLS_VERSION_13);
    ep += 2;

    ep = appendClientHelloSignatureAlgorithms(ext_buf[0..], ep);

    ep = appendClientHelloPskKeyExchangeModes(ext_buf[0..], ep);

    // supported_groups: X25519 first (matches our only key_share so the server picks it
    // without an HRR), plus secp256r1 so servers backed by ngtcp2/BoringSSL whose
    // libp2p TLS cert is on P-256 (e.g. c-lean-libp2p / lantern) don't silently drop
    // the Initial. rustls/quinn accepts a supported_groups superset of key_share.
    writeU16(ext_buf[ep..], EXT_SUPPORTED_GROUPS);
    ep += 2;
    writeU16(ext_buf[ep..], 6); // ext data: list_len(2) + 2 groups * 2
    ep += 2;
    writeU16(ext_buf[ep..], 4); // list len: 2 groups * 2 bytes
    ep += 2;
    writeU16(ext_buf[ep..], GROUP_X25519);
    ep += 2;
    writeU16(ext_buf[ep..], GROUP_SECP256R1);
    ep += 2;

    // key_share: X25519
    writeU16(ext_buf[ep..], EXT_KEY_SHARE);
    ep += 2;
    writeU16(ext_buf[ep..], 38); // 2 (list_len) + 2 (group) + 2 (key_len) + 32 (key)
    ep += 2;
    writeU16(ext_buf[ep..], 36); // list len
    ep += 2;
    writeU16(ext_buf[ep..], GROUP_X25519);
    ep += 2;
    writeU16(ext_buf[ep..], 32);
    ep += 2;
    @memcpy(ext_buf[ep .. ep + 32], client_x25519_pub);
    ep += 32;

    // QUIC transport params — RFC 9001 ext type (quinn/rustls expects 0x0039)
    writeU16(ext_buf[ep..], EXT_QUIC_TRANSPORT_PARAMS);
    ep += 2;
    writeU16(ext_buf[ep..], @intCast(quic_transport_params.len));
    ep += 2;
    @memcpy(ext_buf[ep .. ep + quic_transport_params.len], quic_transport_params);
    ep += quic_transport_params.len;

    // ALPN (if any)
    if (alpn) |a| {
        writeU16(ext_buf[ep..], EXT_ALPN);
        ep += 2;
        const adata_len: u16 = @intCast(2 + 1 + a.len);
        writeU16(ext_buf[ep..], adata_len);
        ep += 2;
        writeU16(ext_buf[ep..], @intCast(1 + a.len));
        ep += 2;
        ext_buf[ep] = @intCast(a.len);
        ep += 1;
        @memcpy(ext_buf[ep .. ep + a.len], a);
        ep += a.len;
    }

    // Body: version(2) + random(32) + sid_len(1) + cs_list + comp(2) + exts(2+ep)
    // cipher suites: 2 (list_len) + 2*num_suites (suite values)
    // When prefer_chacha20 is true, advertise both suites (4 bytes of data).
    const cs_data_len: usize = if (prefer_chacha20) 4 else 2;
    const body_len = 2 + 32 + 1 + (2 + cs_data_len) + 2 + 2 + ep;
    if (out.len < 4 + body_len) return error.BufferTooSmall;

    var pos: usize = writeHsMsgHeader(out, 0, MSG_CLIENT_HELLO, body_len);
    writeU16(out[pos..], TLS_LEGACY_VERSION);
    pos += 2;
    @memcpy(out[pos .. pos + 32], &client_random);
    pos += 32;
    out[pos] = 0; // session_id = empty
    pos += 1;
    writeU16(out[pos..], @intCast(cs_data_len)); // cipher_suites list byte length
    pos += 2;
    if (prefer_chacha20) {
        writeU16(out[pos..], TLS_CHACHA20_POLY1305_SHA256);
        pos += 2;
        writeU16(out[pos..], TLS_AES_128_GCM_SHA256);
        pos += 2;
    } else {
        writeU16(out[pos..], TLS_AES_128_GCM_SHA256);
        pos += 2;
    }
    out[pos] = 1; // compression methods length
    pos += 1;
    out[pos] = 0; // no compression
    pos += 1;
    writeU16(out[pos..], @intCast(ep));
    pos += 2;
    @memcpy(out[pos .. pos + ep], ext_buf[0..ep]);
    pos += ep;
    return pos;
}

// ── Server handshake state machine ───────────────────────────────────────────

/// Upper bound for captured peer leaf certificate (TLS mutual auth / libp2p).
pub const max_peer_leaf_cert_bytes: usize = 16384;

/// Server-side TLS 1.3 handshake state for QUIC.
pub const ServerHandshake = struct {
    /// Ephemeral X25519 key pair (one per connection).
    kp: X25519.KeyPair,
    /// Rolling SHA-256 transcript of all handshake messages.
    transcript: Sha256,
    /// Derived traffic secrets (valid after processClientHello succeeds).
    secrets: TrafficSecrets,
    /// Intermediate handshake secret for app key derivation.
    handshake_secret: [32]u8,
    /// Saved ClientHello for reference (e.g., session_id echo).
    ch: ClientHelloData,
    /// True once server flight is built and client Finished is verified.
    handshake_done: bool,
    /// SHA-256(ClientHello) captured before ServerHello is added to transcript.
    /// Used for client_early_traffic_secret derivation (RFC 8446 §7.1).
    ch_hash: [32]u8,
    /// True if the client offered a PSK identity and we echoed pre_shared_key
    /// in the ServerHello.  When true, buildServerFlight skips Certificate and
    /// CertificateVerify (RFC 8446 §4.2.11 / §4.4).
    accept_psk: bool,
    /// Client leaf (DER) when the client sends a `Certificate` message (mutual TLS).
    peer_leaf_cert_der: [max_peer_leaf_cert_bytes]u8 = undefined,
    peer_leaf_cert_der_len: u16 = 0,
    /// Encoded QUIC transport parameters extension body from the client's
    /// ClientHello message (RFC 9001 §8.2). Populated in `processClientHello`.
    /// See `ClientHandshake.peer_qtp` for the size rationale.
    peer_qtp: [512]u8 = undefined,
    peer_qtp_len: u16 = 0,
    /// HelloRetryRequest state. `sent_hrr` prevents a second HRR (RFC 8446
    /// §4.1.4 permits at most one). `hrr_pending` signals to the QUIC layer
    /// that the most recent `processClientHello` produced an HRR — it must be
    /// sent as the server Initial, and handshake keys / server flight must NOT
    /// be derived yet (they come after the client's second ClientHello).
    sent_hrr: bool = false,
    hrr_pending: bool = false,

    pub fn init() ServerHandshake {
        return .{
            .kp = blk: {
                var seed: [X25519.seed_length]u8 = undefined;
                compat.random.bytes(&seed);
                break :blk X25519.KeyPair.generateDeterministic(seed) catch unreachable;
            },
            .transcript = Sha256.init(.{}),
            .secrets = .{},
            .handshake_secret = [_]u8{0} ** 32,
            .ch = .{},
            .handshake_done = false,
            .ch_hash = [_]u8{0} ** 32,
            .accept_psk = false,
        };
    }

    /// Process a received ClientHello.
    /// Writes ServerHello bytes to `out_initial` (for Initial CRYPTO frame).
    /// Returns bytes written.
    pub fn processClientHello(
        self: *ServerHandshake,
        ch_bytes: []const u8,
        out_initial: []u8,
    ) !usize {
        self.ch = try parseClientHello(ch_bytes);

        // HelloRetryRequest (RFC 8446 §4.1.4): the client sent no X25519
        // key_share. If it nonetheless listed X25519 in supported_groups (as
        // AWS-LC/BoringSSL do — they lead their key_share with the
        // X25519MLKEM768 PQ hybrid), ask it to retry with X25519. Otherwise we
        // truly cannot agree on a group.
        if (self.ch.x25519_key == null) {
            if (self.ch.x25519_supported_group and !self.sent_hrr) {
                // Transcript rewrite (RFC 8446 §4.4.1): replace ClientHello1
                // with the synthetic "message_hash" message, then append the
                // HelloRetryRequest. Subsequent messages (ClientHello2,
                // ServerHello, ...) extend this transcript.
                var h1_ctx = Sha256.init(.{});
                h1_ctx.update(ch_bytes);
                const h1 = peekHash(h1_ctx);
                self.transcript = Sha256.init(.{});
                var synth: [4 + 32]u8 = undefined;
                synth[0] = MSG_MESSAGE_HASH;
                synth[1] = 0;
                synth[2] = 0;
                synth[3] = 32;
                @memcpy(synth[4..], &h1);
                self.transcript.update(&synth);

                const hrr_len = try buildHelloRetryRequest(
                    out_initial,
                    self.ch.session_id[0..self.ch.session_id_len],
                    self.ch.cipher_suite,
                    GROUP_X25519,
                );
                self.transcript.update(out_initial[0..hrr_len]);
                self.sent_hrr = true;
                self.hrr_pending = true;
                return hrr_len;
            }
            return error.NoKeyShare;
        }
        // Normal ServerHello path (this may be the client's SECOND ClientHello
        // after an HRR, in which case the transcript already holds
        // message_hash(CH1) || HelloRetryRequest and update() below appends CH2).
        self.hrr_pending = false;

        // Capture the peer's QUIC transport parameters before `ch_bytes`
        // ownership escapes us (see ClientHandshake.peer_qtp for rationale).
        if (self.ch.quic_transport_params) |qtp| {
            if (qtp.len <= self.peer_qtp.len and qtp.offset + qtp.len <= ch_bytes.len) {
                @memcpy(self.peer_qtp[0..qtp.len], ch_bytes[qtp.offset .. qtp.offset + qtp.len]);
                self.peer_qtp_len = @intCast(qtp.len);
            }
        }

        // Add ClientHello to transcript
        self.transcript.update(ch_bytes);

        // Capture transcript hash after ClientHello for early traffic secret derivation.
        // Must be done BEFORE ServerHello is added (RFC 8446 §7.1 "Messages" = up to CH).
        self.ch_hash = peekHash(self.transcript);

        // ServerHello → Initial CRYPTO.
        // Include pre_shared_key extension if the client sent a PSK identity,
        // signalling that PSK session resumption was accepted (RFC 8446 §4.2.11).
        self.accept_psk = self.ch.psk_identity_len > 0;
        const n = try buildServerHello(
            out_initial,
            self.ch.session_id[0..self.ch.session_id_len],
            self.ch.cipher_suite,
            &self.kp.public_key,
            self.accept_psk,
        );

        // Add ServerHello to transcript
        self.transcript.update(out_initial[0..n]);

        // Compute ECDHE
        const shared = try X25519.scalarmult(
            self.kp.secret_key,
            self.ch.x25519_key.?,
        );

        // Derive handshake secrets
        self.handshake_secret = deriveHandshakeSecret(shared);
        const hello_hash = peekHash(self.transcript);
        self.secrets.client_handshake = deriveTrafficSecret(
            self.handshake_secret,
            "c hs traffic",
            &hello_hash,
        );
        self.secrets.server_handshake = deriveTrafficSecret(
            self.handshake_secret,
            "s hs traffic",
            &hello_hash,
        );

        return n;
    }

    /// Build EncryptedExtensions + Certificate + CertificateVerify + Finished.
    /// These are raw plaintext bytes for Handshake CRYPTO frames.
    /// Also derives application traffic secrets.
    pub fn buildServerFlight(
        self: *ServerHandshake,
        cert_der: []const u8,
        private_key: *const tls_vendor.config.PrivateKey,
        quic_tp: []const u8,
        alpn: ?[]const u8,
        request_client_certificate: bool,
        out: []u8,
    ) !usize {
        var pos: usize = 0;

        // EncryptedExtensions: mirror rustls/quinn — only extensions the client offered.
        const ee_alpn = negotiateEeAlpn(&self.ch, alpn);
        const ee_early = eeAcceptEarlyData(&self.ch, self.accept_psk);
        const ee_len = try buildEncryptedExtensions(
            out[pos..],
            quic_tp,
            self.ch.quic_transport_params_ext_type,
            ee_alpn,
            ee_early,
        );
        self.transcript.update(out[pos .. pos + ee_len]);
        pos += ee_len;

        // RFC 8446 §4.4: when PSK is in use the server authenticates via the
        // PSK binder, not via a certificate.  Skip Certificate + CertificateVerify.
        if (!self.accept_psk) {
            if (request_client_certificate) {
                const cr_len = try buildCertificateRequest(out[pos..]);
                self.transcript.update(out[pos .. pos + cr_len]);
                pos += cr_len;
            }
            // Certificate
            const cert_len = try buildCertificate(out[pos..], cert_der);
            self.transcript.update(out[pos .. pos + cert_len]);
            pos += cert_len;

            // CertificateVerify (signs transcript through Certificate)
            const cv_hash = peekHash(self.transcript);
            const cv_len = try buildCertificateVerify(out[pos..], &cv_hash, private_key);
            self.transcript.update(out[pos .. pos + cv_len]);
            pos += cv_len;
        }

        // Finished
        const fin_hash = peekHash(self.transcript);
        const fin_len = buildFinished(out[pos..], self.secrets.server_handshake, &fin_hash);
        self.transcript.update(out[pos .. pos + fin_len]);
        pos += fin_len;

        // Derive application secrets now (needed before client Finished)
        const hs_hash = peekHash(self.transcript);
        const master = deriveMasterSecret(self.handshake_secret);
        self.secrets.client_app = deriveTrafficSecret(master, "c ap traffic", &hs_hash);
        self.secrets.server_app = deriveTrafficSecret(master, "s ap traffic", &hs_hash);

        return pos;
    }

    /// Derive the resumption secret for NewSessionTicket (RFC 8446 §7.5).
    pub fn resumptionSecret(self: *const ServerHandshake) [32]u8 {
        const final_hash = peekHash(self.transcript);
        const master = deriveMasterSecret(self.handshake_secret);
        return deriveTrafficSecret(master, "res master", &final_hash);
    }

    /// Process the client's post-server-flight TLS messages: either a single `Finished`
    /// (HTTP-style zquic clients) or `Certificate` + `CertificateVerify` + `Finished` (mutual TLS).
    pub fn processClientHandshakeInbound(self: *ServerHandshake, data: []const u8) !void {
        if (data.len >= 4 and data[0] == MSG_CERTIFICATE) {
            var p: usize = 0;
            while (p + 4 <= data.len) {
                const msg_type = data[p];
                const msg_len = readU24(data[p + 1 ..]);
                const msg_end = p + 4 + msg_len;
                if (msg_end > data.len) return error.TruncatedMessage;
                const msg = data[p..msg_end];
                switch (msg_type) {
                    MSG_CERTIFICATE => {
                        self.transcript.update(msg);
                        if (self.peer_leaf_cert_der_len == 0) {
                            if (try leafCertificateDerFromCertificateHandshakeMessageOptional(msg)) |leaf| {
                                if (leaf.len > max_peer_leaf_cert_bytes) return error.PeerLeafCertificateTooLarge;
                                @memcpy(self.peer_leaf_cert_der[0..leaf.len], leaf);
                                self.peer_leaf_cert_der_len = @intCast(leaf.len);
                            }
                        }
                    },
                    MSG_CERTIFICATE_VERIFY => {
                        if (self.peer_leaf_cert_der_len == 0) return error.BadCertificateVerify;
                        const th = peekHash(self.transcript);
                        const leaf = self.peer_leaf_cert_der[0..self.peer_leaf_cert_der_len];
                        try verifyClientCertificateVerifyMessage(msg, leaf, &th);
                        self.transcript.update(msg);
                    },
                    MSG_FINISHED => {
                        try self.processClientFinished(msg);
                        return;
                    },
                    else => return error.BadMessageType,
                }
                p = msg_end;
            }
            return error.TruncatedMessage;
        }
        try self.processClientFinished(data);
    }

    /// Verify the client's Finished message (raw bytes).
    pub fn processClientFinished(self: *ServerHandshake, fin_bytes: []const u8) !void {
        if (fin_bytes.len < 4) return error.TruncatedMessage;
        if (fin_bytes[0] != MSG_FINISHED) return error.UnexpectedMessage;
        const vd_len = readU24(fin_bytes[1..4]);
        if (vd_len != 32) return error.BadFinishedLength;
        if (fin_bytes.len < 4 + vd_len) return error.TruncatedMessage;
        const verify_data = fin_bytes[4 .. 4 + vd_len];

        const expected = computeFinishedVerifyData(
            self.secrets.client_handshake,
            &peekHash(self.transcript),
        );
        const recv: [32]u8 = verify_data[0..32].*;
        if (!std.crypto.timing_safe.eql([32]u8, recv, expected)) return error.BadFinishedMac;

        self.transcript.update(fin_bytes);
        self.handshake_done = true;
    }
};

// ── Client handshake state machine ───────────────────────────────────────────

/// Optional client certificate + key for TLS 1.3 mutual authentication (e.g. libp2p QUIC).
pub const ClientMutualTlsCredentials = struct {
    cert_der: []const u8,
    private_key: *const tls_vendor.config.PrivateKey,
};

/// Client-side TLS 1.3 handshake state for QUIC.
pub const ClientHandshake = struct {
    kp: X25519.KeyPair,
    transcript: Sha256,
    secrets: TrafficSecrets,
    handshake_secret: [32]u8,
    handshake_done: bool,
    /// Cipher suite chosen by the server (set after processServerHello).
    cipher_suite: u16 = TLS_AES_128_GCM_SHA256,
    /// The 32-byte random value from ClientHello (needed for NSS keylog format).
    client_random: [32]u8 = [_]u8{0} ** 32,
    /// Server leaf certificate (DER) from the first `Certificate` message in the server flight.
    peer_leaf_cert_der: [max_peer_leaf_cert_bytes]u8 = undefined,
    peer_leaf_cert_der_len: u16 = 0,
    /// Encoded QUIC transport parameters extension body from the server's
    /// EncryptedExtensions message (RFC 9001 §8.2). Captured in
    /// `processServerFlight`. `peer_qtp_len == 0` means absent or oversize
    /// (peers exceeding 512 bytes are silently dropped — the spec ceiling
    /// is 65535, but no real-world deployment exceeds a few hundred).
    peer_qtp: [512]u8 = undefined,
    peer_qtp_len: u16 = 0,

    pub fn init() ClientHandshake {
        return .{
            .kp = blk: {
                var seed: [X25519.seed_length]u8 = undefined;
                compat.random.bytes(&seed);
                break :blk X25519.KeyPair.generateDeterministic(seed) catch unreachable;
            },
            .transcript = Sha256.init(.{}),
            .secrets = .{},
            .handshake_secret = [_]u8{0} ** 32,
            .handshake_done = false,
        };
    }

    /// Build ClientHello bytes for Initial CRYPTO frame.
    pub fn buildClientHelloMsg(
        self: *ClientHandshake,
        out: []u8,
        quic_tp: []const u8,
        alpn: ?[]const u8,
        server_name: ?[]const u8,
    ) !usize {
        const n = try buildClientHello(out, &self.kp.public_key, quic_tp, alpn, server_name);
        self.transcript.update(out[0..n]);
        // ClientHello layout: type(1) + len(3) + legacy_version(2) + random(32)
        if (n >= 6 + 32) @memcpy(&self.client_random, out[6..38]);
        return n;
    }

    /// Variant that advertises ChaCha20-Poly1305 as the preferred cipher suite.
    pub fn buildClientHelloMsgChaCha20(
        self: *ClientHandshake,
        out: []u8,
        quic_tp: []const u8,
        alpn: ?[]const u8,
        server_name: ?[]const u8,
    ) !usize {
        const n = try buildClientHelloChaCha20(out, &self.kp.public_key, quic_tp, alpn, server_name);
        self.transcript.update(out[0..n]);
        if (n >= 6 + 32) @memcpy(&self.client_random, out[6..38]);
        return n;
    }

    /// Build a ClientHello with a PSK extension for session resumption.
    /// Updates the TLS transcript with the full ClientHello (including binder).
    pub fn buildClientHelloMsgWithPsk(
        self: *ClientHandshake,
        out: []u8,
        quic_tp: []const u8,
        alpn: ?[]const u8,
        server_name: ?[]const u8,
        psk_info: PskInfo,
    ) !usize {
        const n = try buildClientHelloWithPsk(out, &self.kp.public_key, quic_tp, alpn, server_name, psk_info, false, false);
        self.transcript.update(out[0..n]);
        if (n >= 6 + 32) @memcpy(&self.client_random, out[6..38]);
        return n;
    }

    /// Build a ClientHello with PSK + early_data extension for 0-RTT.
    /// Updates the TLS transcript; returns the message length and the HKDF
    /// early_secret (= HKDF-Extract(0, PSK)) so the caller can derive the
    /// client_early_traffic_secret using the ClientHello transcript hash.
    pub fn buildClientHelloMsgWithPskAndEarlyData(
        self: *ClientHandshake,
        out: []u8,
        quic_tp: []const u8,
        alpn: ?[]const u8,
        server_name: ?[]const u8,
        psk_info: PskInfo,
    ) !struct { n: usize, early_secret: [32]u8 } {
        const n = try buildClientHelloWithPsk(out, &self.kp.public_key, quic_tp, alpn, server_name, psk_info, false, true);
        self.transcript.update(out[0..n]);
        if (n >= 6 + 32) @memcpy(&self.client_random, out[6..38]);
        // Derive early_secret = HKDF-Extract(zeros_32, PSK).
        // The caller combines this with peekHash(transcript) to get the
        // client_early_traffic_secret.
        const zeros: [32]u8 = .{0} ** 32;
        const early_secret = HkdfSha256.extract(&zeros, &psk_info.psk);
        return .{ .n = n, .early_secret = early_secret };
    }

    /// Process ServerHello bytes. Derives handshake secrets.
    pub fn processServerHello(self: *ClientHandshake, sh_bytes: []const u8) !void {
        if (sh_bytes.len < 4) return error.TruncatedMessage;
        if (sh_bytes[0] != MSG_SERVER_HELLO) return error.BadMessageType;
        const body_len = readU24(sh_bytes[1..4]);
        const body = sh_bytes[4 .. 4 + body_len];

        // Skip: version(2) + random(32) + sid_len(1) + sid + cs(2) + comp(1)
        var p: usize = 2 + 32;
        const sid_len = body[p];
        p += 1 + sid_len;
        if (p + 3 <= body.len) {
            self.cipher_suite = readU16(body[p..]);
        }
        p += 2 + 1; // cipher_suite + compression

        // Parse extensions for key_share
        const ext_total = readU16(body[p..]);
        p += 2;
        const ext_end = p + ext_total;
        var server_x25519: ?[32]u8 = null;

        while (p + 4 <= ext_end) {
            const ext_type = readU16(body[p..]);
            const ext_len = readU16(body[p + 2 ..]);
            p += 4;
            const ext_data = body[p .. p + ext_len];
            if (ext_type == EXT_KEY_SHARE and ext_data.len >= 36) {
                const group = readU16(ext_data);
                if (group == GROUP_X25519) {
                    const klen = readU16(ext_data[2..]);
                    if (klen == 32) {
                        server_x25519 = ext_data[4..36].*;
                    }
                }
            }
            p += ext_len;
        }

        if (server_x25519 == null) return error.NoKeyShare;
        self.transcript.update(sh_bytes);

        const shared = try X25519.scalarmult(
            self.kp.secret_key,
            server_x25519.?,
        );
        self.handshake_secret = deriveHandshakeSecret(shared);
        const hello_hash = peekHash(self.transcript);
        self.secrets.client_handshake = deriveTrafficSecret(
            self.handshake_secret,
            "c hs traffic",
            &hello_hash,
        );
        self.secrets.server_handshake = deriveTrafficSecret(
            self.handshake_secret,
            "s hs traffic",
            &hello_hash,
        );
    }

    /// Process server Handshake messages (EncryptedExtensions, Certificate,
    /// CertificateVerify, Finished). Certificate is NOT verified — accepts any.
    /// Returns bytes to send in Handshake CRYPTO frames: `Finished` only, or
    /// `Certificate` + `CertificateVerify` + `Finished` when `mutual` is non-null.
    pub fn processServerFlight(
        self: *ClientHandshake,
        hs_bytes: []const u8,
        out: []u8,
        mutual: ?ClientMutualTlsCredentials,
    ) !usize {
        // Walk through messages
        var p: usize = 0;
        var found_finished = false;
        var saw_certificate_request = false;
        while (p + 4 <= hs_bytes.len) {
            const msg_type = hs_bytes[p];
            const msg_len = readU24(hs_bytes[p + 1 ..]);
            const msg_end = p + 4 + msg_len;
            if (msg_end > hs_bytes.len) break;

            const msg = hs_bytes[p..msg_end];
            switch (msg_type) {
                MSG_ENCRYPTED_EXTENSIONS, MSG_CERTIFICATE_VERIFY, MSG_CERTIFICATE_REQUEST => {
                    if (msg_type == MSG_CERTIFICATE_REQUEST) saw_certificate_request = true;
                    if (msg_type == MSG_ENCRYPTED_EXTENSIONS) {
                        // Best-effort: extract the peer's QUIC transport parameters
                        // extension. Failures are silent — `peer_qtp_len == 0` then
                        // signals the caller to fall back to RFC defaults.
                        if (extractQuicTpFromEncryptedExtensions(msg)) |qtp| {
                            if (qtp.len <= self.peer_qtp.len) {
                                @memcpy(self.peer_qtp[0..qtp.len], qtp);
                                self.peer_qtp_len = @intCast(qtp.len);
                            }
                        }
                    }
                    self.transcript.update(msg);
                },
                MSG_CERTIFICATE => {
                    self.transcript.update(msg);
                    if (self.peer_leaf_cert_der_len == 0) {
                        const leaf = try leafCertificateDerFromCertificateHandshakeMessage(msg);
                        if (leaf.len > max_peer_leaf_cert_bytes) return error.PeerLeafCertificateTooLarge;
                        @memcpy(self.peer_leaf_cert_der[0..leaf.len], leaf);
                        self.peer_leaf_cert_der_len = @intCast(leaf.len);
                    }
                },
                MSG_FINISHED => {
                    // Verify server Finished
                    const expected = computeFinishedVerifyData(
                        self.secrets.server_handshake,
                        &peekHash(self.transcript),
                    );
                    if (msg_len != 32) return error.BadFinishedLength;
                    const vd = msg[4 .. 4 + msg_len];
                    const recv: [32]u8 = vd[0..32].*;
                    if (!std.crypto.timing_safe.eql([32]u8, recv, expected)) return error.BadFinishedMac;
                    self.transcript.update(msg);

                    // Derive app secrets
                    const hs_hash = peekHash(self.transcript);
                    const master = deriveMasterSecret(self.handshake_secret);
                    self.secrets.client_app = deriveTrafficSecret(master, "c ap traffic", &hs_hash);
                    self.secrets.server_app = deriveTrafficSecret(master, "s ap traffic", &hs_hash);

                    found_finished = true;
                },
                else => {},
            }
            p = msg_end;
        }

        if (!found_finished) return error.NoServerFinished;

        if (mutual) |m| {
            var out_pos: usize = 0;
            const cert_len = try buildCertificate(out[out_pos..], m.cert_der);
            self.transcript.update(out[out_pos..][0..cert_len]);
            out_pos += cert_len;

            const cv_hash = peekHash(self.transcript);
            const cv_len = try buildClientCertificateVerify(out[out_pos..], &cv_hash, m.private_key);
            self.transcript.update(out[out_pos..][0..cv_len]);
            out_pos += cv_len;

            const fin_hash = peekHash(self.transcript);
            const fin_len = buildFinished(out[out_pos..], self.secrets.client_handshake, &fin_hash);
            self.transcript.update(out[out_pos..][0..fin_len]);
            out_pos += fin_len;
            self.handshake_done = true;
            return out_pos;
        }

        if (saw_certificate_request) {
            var out_pos: usize = 0;
            const cert_len = try buildEmptyCertificate(out[out_pos..]);
            self.transcript.update(out[out_pos..][0..cert_len]);
            out_pos += cert_len;

            const fin_hash = peekHash(self.transcript);
            const fin_len = buildFinished(out[out_pos..], self.secrets.client_handshake, &fin_hash);
            self.transcript.update(out[out_pos..][0..fin_len]);
            out_pos += fin_len;
            self.handshake_done = true;
            return out_pos;
        }

        const client_fin_hash = peekHash(self.transcript);
        const n = buildFinished(out, self.secrets.client_handshake, &client_fin_hash);
        self.transcript.update(out[0..n]);
        self.handshake_done = true;
        return n;
    }
};

// ── QUIC key material derivation ─────────────────────────────────────────────

/// QUIC key material derived from a TLS 1.3 traffic secret.
///
/// Both AES-128-GCM (16-byte key) and ChaCha20-Poly1305 (32-byte key) are
/// derived unconditionally so the struct can serve either cipher suite.
/// RFC 9001 §5.1: key_len = 16 for AES-128-GCM, 32 for ChaCha20-Poly1305.
pub const QuicKeyMaterial = struct {
    key: [16]u8, // AES-128-GCM key (16 bytes)
    key32: [32]u8, // ChaCha20-Poly1305 key (32 bytes)
    iv: [12]u8, // nonce base (same length for both suites)
    hp: [16]u8, // header protection key for AES-128 HP
    hp32: [32]u8, // header protection key for ChaCha20 HP (32 bytes)
};

/// Build a TLS 1.3 NewSessionTicket message.
///
/// Format (RFC 8446 §4.6.1):
///   msg type (1) | length (3) | lifetime (4) | age_add (4) |
///   nonce len (1) | nonce | ticket len (2) | ticket | extensions (2)
pub fn buildNewSessionTicket(
    out: []u8,
    lifetime_s: u32,
    nonce: []const u8,
    ticket: []const u8,
    max_early_data: u32,
) error{BufferTooSmall}!usize {
    const ext_len: usize = if (max_early_data > 0) 8 else 2; // early_data ext or empty
    const body_len = 4 + 4 + 1 + nonce.len + 2 + ticket.len + ext_len;
    if (out.len < 4 + body_len) return error.BufferTooSmall;
    var pos: usize = 0;
    out[pos] = 0x04; // msg_type = new_session_ticket
    pos += 1;
    writeU24(out[pos..], @intCast(body_len));
    pos += 3;
    std.mem.writeInt(u32, out[pos..][0..4], lifetime_s, .big);
    pos += 4;
    std.mem.writeInt(u32, out[pos..][0..4], 0, .big); // ticket_age_add = 0
    pos += 4;
    out[pos] = @intCast(nonce.len);
    pos += 1;
    @memcpy(out[pos .. pos + nonce.len], nonce);
    pos += nonce.len;
    std.mem.writeInt(u16, out[pos..][0..2], @intCast(ticket.len), .big);
    pos += 2;
    @memcpy(out[pos .. pos + ticket.len], ticket);
    pos += ticket.len;
    if (max_early_data > 0) {
        // early_data extension: type 0x002a, len 4, max_early_data_size
        std.mem.writeInt(u16, out[pos..][0..2], 6, .big); // extensions total length
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 0x002a, .big); // ext type
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 4, .big); // ext data length
        pos += 2;
        std.mem.writeInt(u32, out[pos..][0..4], max_early_data, .big);
        pos += 4;
    } else {
        std.mem.writeInt(u16, out[pos..][0..2], 0, .big); // empty extensions
        pos += 2;
    }
    return pos;
}

/// Derive QUIC key material from a TLS 1.3 traffic secret (RFC 9001 §5.1).
///
/// Both the 16-byte AES key and the 32-byte ChaCha20 key are derived from the
/// same "quic key" label — HKDF-Expand-Label simply outputs the requested
/// number of bytes, so the 32-byte version is a superset of the 16-byte one.
/// Deriving both unconditionally avoids branching on cipher suite here and
/// lets callers choose the correct field at use time.
pub fn deriveQuicKeys(traffic_secret: [32]u8) QuicKeyMaterial {
    var km: QuicKeyMaterial = undefined;
    keys_mod.hkdfExpandLabel(&km.key, &traffic_secret, "quic key", "");
    keys_mod.hkdfExpandLabel(&km.key32, &traffic_secret, "quic key", "");
    keys_mod.hkdfExpandLabel(&km.iv, &traffic_secret, "quic iv", "");
    keys_mod.hkdfExpandLabel(&km.hp, &traffic_secret, "quic hp", "");
    keys_mod.hkdfExpandLabel(&km.hp32, &traffic_secret, "quic hp", "");
    return km;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "handshake: key schedule" {
    const testing = std.testing;
    // Just verify no crash for now; deeper vectors in integration test.
    const ecdhe = [_]u8{0x42} ** 32;
    const hs = deriveHandshakeSecret(ecdhe);
    const master = deriveMasterSecret(hs);
    const hello_hash = [_]u8{0xAB} ** 32;
    const client_hs = deriveTrafficSecret(hs, "c hs traffic", &hello_hash);
    const server_hs = deriveTrafficSecret(hs, "s hs traffic", &hello_hash);
    const client_ap = deriveTrafficSecret(master, "c ap traffic", &hello_hash);
    const server_ap = deriveTrafficSecret(master, "s ap traffic", &hello_hash);
    // All should be distinct
    try testing.expect(!std.mem.eql(u8, &client_hs, &server_hs));
    try testing.expect(!std.mem.eql(u8, &client_ap, &server_ap));
    try testing.expect(!std.mem.eql(u8, &client_hs, &client_ap));
}

test "handshake: EE ALPN only when client offered (rustls/quinn)" {
    const testing = std.testing;
    var ch: ClientHelloData = .{};
    try testing.expect(eeAlpnMatchingClientOffer(&ch, ALPN_H3) == null);
    try testing.expect(eeAlpnMatchingClientOffer(&ch, ALPN_H09) == null);
    ch.alpn_h3 = true;
    try testing.expectEqualSlices(u8, ALPN_H3, eeAlpnMatchingClientOffer(&ch, ALPN_H3).?);
    ch.alpn_h3 = false;
    ch.alpn_h09 = true;
    try testing.expectEqualSlices(u8, ALPN_H09, eeAlpnMatchingClientOffer(&ch, ALPN_H09).?);
}

test "handshake: negotiateEeAlpn falls back to hq-interop for quinn interop" {
    const testing = std.testing;
    var ch: ClientHelloData = .{ .alpn_h09 = true };
    try testing.expectEqualSlices(u8, ALPN_H09, negotiateEeAlpn(&ch, ALPN_H3).?);
}

test "handshake: EE ALPN echoes arbitrary preferred proto (libp2p QUIC)" {
    const testing = std.testing;
    // ProtocolNameList inner: u8 len + bytes, repeated. Client offers
    // "libp2p" (6 bytes) — what go-libp2p's QUIC dialer sends.
    var ch: ClientHelloData = .{};
    const libp2p_proto: []const u8 = "libp2p";
    ch.alpn_protos[0] = @intCast(libp2p_proto.len);
    @memcpy(ch.alpn_protos[1 .. 1 + libp2p_proto.len], libp2p_proto);
    ch.alpn_protos_len = 1 + libp2p_proto.len;

    // Server prefers "libp2p" — pre-fix this returned null because the
    // matcher only knew ALPN_H3 / ALPN_H09. Post-fix it must echo the
    // proto so go-libp2p sees the ALPN in EncryptedExtensions and the
    // TLS handshake completes.
    const got = eeAlpnMatchingClientOffer(&ch, libp2p_proto).?;
    try testing.expectEqualSlices(u8, libp2p_proto, got);

    // Mismatched preferred → no echo (don't lie to the client).
    try testing.expect(eeAlpnMatchingClientOffer(&ch, ALPN_H3) == null);
}

test "handshake: EE ALPN matcher walks multi-proto offer list" {
    const testing = std.testing;
    // Client offers ["h3", "libp2p"] — proves the matcher iterates past
    // a non-match (h3) when the server prefers an unknown-to-zquic proto
    // (libp2p). Pre-fix this returned null because the fast-path only
    // matched ALPN_H3 (which was offered) and not the second entry.
    var ch: ClientHelloData = .{};
    // u8 len + bytes, repeated. First "h3", then "libp2p".
    const offers = [_]u8{ 2, 'h', '3', 6, 'l', 'i', 'b', 'p', '2', 'p' };
    @memcpy(ch.alpn_protos[0..offers.len], &offers);
    ch.alpn_protos_len = offers.len;
    // Also flag h3 because the parser would have. The fast-path must
    // NOT short-circuit to h3 when h3 is offered but the server
    // prefers libp2p.
    ch.alpn_h3 = true;

    try testing.expectEqualSlices(u8, "libp2p", eeAlpnMatchingClientOffer(&ch, "libp2p").?);
    // Sanity: when the server actually prefers h3, the fast-path
    // still returns it.
    try testing.expectEqualSlices(u8, ALPN_H3, eeAlpnMatchingClientOffer(&ch, ALPN_H3).?);
    // Proto the client did NOT offer is not echoed.
    try testing.expect(eeAlpnMatchingClientOffer(&ch, "doesnotexist") == null);
}

test "handshake: EE early_data only on accepted PSK (rustls decide_if_early_data_allowed)" {
    const testing = std.testing;
    var ch: ClientHelloData = .{ .has_early_data = true };
    try testing.expect(!eeAcceptEarlyData(&ch, false));
    try testing.expect(eeAcceptEarlyData(&ch, true));
}

test "handshake: EncryptedExtensions wire encoding omits unsolicited ALPN" {
    const testing = std.testing;
    var buf_alpn: [512]u8 = undefined;
    var buf_no_alpn: [512]u8 = undefined;
    const tp = [_]u8{ 0x05, 0x00, 0x00, 0x00, 0x00 }; // minimal QUIC TP blob
    const with_alpn = try buildEncryptedExtensions(&buf_alpn, &tp, EXT_QUIC_TRANSPORT_PARAMS, ALPN_H3, false);
    const without_alpn = try buildEncryptedExtensions(&buf_no_alpn, &tp, EXT_QUIC_TRANSPORT_PARAMS, null, false);
    try testing.expect(eeExtensionsContainType(buf_alpn[0..with_alpn], EXT_ALPN));
    try testing.expect(!eeExtensionsContainType(buf_no_alpn[0..without_alpn], EXT_ALPN));
    try testing.expect(eeExtensionsContainType(buf_no_alpn[0..without_alpn], EXT_QUIC_TRANSPORT_PARAMS));
}

test "handshake: EncryptedExtensions echoes client QUIC TP extension type (quinn/rustls)" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;
    const tp = [_]u8{ 0x05, 0x00, 0x00, 0x00, 0x00 };
    const ee_len = try buildEncryptedExtensions(&buf, &tp, EXT_QUIC_TRANSPORT_PARAMS_DRAFT, null, false);
    try testing.expect(eeExtensionsContainType(buf[0..ee_len], EXT_QUIC_TRANSPORT_PARAMS_DRAFT));
    try testing.expect(!eeExtensionsContainType(buf[0..ee_len], EXT_QUIC_TRANSPORT_PARAMS));
}

fn eeExtensionsContainType(ee_msg: []const u8, ext_type: u16) bool {
    if (ee_msg.len < 8 or ee_msg[0] != MSG_ENCRYPTED_EXTENSIONS) return false;
    const body_len = readU24(ee_msg[1..]);
    const ext_list_len = readU16(ee_msg[4..]);
    var p: usize = 6;
    const ext_end = 4 + body_len;
    const list_end = p + ext_list_len;
    if (list_end > ext_end or list_end > ee_msg.len) return false;
    while (p + 4 <= list_end) {
        if (readU16(ee_msg[p..]) == ext_type) return true;
        const elen = readU16(ee_msg[p + 2 ..]);
        p += 4 + elen;
    }
    return false;
}

test "handshake: build and parse ServerHello" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;
    const pub_key = [_]u8{0x55} ** 32;
    const session_id = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const n = try buildServerHello(&buf, &session_id, TLS_AES_128_GCM_SHA256, &pub_key, false);
    try testing.expect(n > 4);
    try testing.expectEqual(MSG_SERVER_HELLO, buf[0]);
}

test "leafCertificateDerFromCertificateHandshakeMessage round trip" {
    const testing = std.testing;
    const der_in = [_]u8{ 0x30, 0x05, 0x30, 0x03, 0x01, 0x02, 0x03 };
    var buf: [256]u8 = undefined;
    const n = try buildCertificate(&buf, &der_in);
    const leaf = try leafCertificateDerFromCertificateHandshakeMessage(buf[0..n]);
    try testing.expectEqualSlices(u8, &der_in, leaf);
}

test "buildCertificateRequest signature_algorithms extension wire format" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    const n = try buildCertificateRequest(&buf);
    try testing.expect(n > 4);
    try testing.expectEqual(MSG_CERTIFICATE_REQUEST, buf[0]);
    // body: ctx_len=0, extensions_len=10, ext type=13, ext_data_len=6, list_len=4, 0x0403, 0x0503
    const body = buf[4..n];
    try testing.expectEqual(@as(u8, 0), body[0]); // empty request context
    try testing.expectEqual(@as(u16, 10), readU16(body[1..])); // extensions block
    try testing.expectEqual(@as(u16, EXT_SIGNATURE_ALGORITHMS), readU16(body[3..]));
    try testing.expectEqual(@as(u16, 6), readU16(body[5..])); // extension data
    try testing.expectEqual(@as(u16, 4), readU16(body[7..])); // SignatureSchemeList length
    try testing.expectEqual(SIG_ECDSA_SECP256R1_SHA256, readU16(body[9..]));
    try testing.expectEqual(SIG_ECDSA_SECP384R1_SHA384, readU16(body[11..]));
}

test "handshake: client-server secrets are mirrored" {
    // Run client and server handshake in memory, verify derived secrets match.
    const testing = std.testing;

    var srv = ServerHandshake.init();
    var cli = ClientHandshake.init();

    // ── ClientHello ──────────────────────────────────────────────────────
    var ch_buf: [1024]u8 = undefined;
    const ch_len = try cli.buildClientHelloMsg(&ch_buf, &.{}, null, null);
    const ch_bytes = ch_buf[0..ch_len];

    // ── ServerHello (Initial) ────────────────────────────────────────────
    var sh_buf: [512]u8 = undefined;
    const sh_len = try srv.processClientHello(ch_bytes, &sh_buf);
    const sh_bytes = sh_buf[0..sh_len];

    // Client processes ServerHello → derives handshake secrets
    try cli.processServerHello(sh_bytes);

    // At this point both sides should have matching handshake secrets
    try testing.expectEqualSlices(u8, &cli.secrets.client_handshake, &srv.secrets.client_handshake);
    try testing.expectEqualSlices(u8, &cli.secrets.server_handshake, &srv.secrets.server_handshake);
}

test "handshake: selectPreferredCipherSuite prefers AES-128 over AES-256" {
    const testing = std.testing;
    // quinn-style ordering: AES-256 first, then AES-128, then ChaCha20.
    const suites = [_]u8{
        0x13, 0x02, 0x13, 0x01, 0x13, 0x03,
    };
    const picked = try selectPreferredCipherSuite(&suites);
    try testing.expectEqual(TLS_AES_128_GCM_SHA256, picked);
}

test "handshake: buildHelloRetryRequest carries HRR random + selected group" {
    const testing = std.testing;
    var out: [128]u8 = undefined;
    const session_id = [_]u8{0xAB} ** 32;
    const n = try buildHelloRetryRequest(&out, &session_id, TLS_AES_128_GCM_SHA256, GROUP_X25519);
    // Handshake header: ServerHello type + 3-byte length.
    try testing.expectEqual(@as(u8, MSG_SERVER_HELLO), out[0]);
    // ServerHello.random (offset 4 legacy_version(2) → random at 6) must be the
    // magic HelloRetryRequest value (RFC 8446 §4.1.3).
    try testing.expect(std.mem.eql(u8, out[6 .. 6 + 32], &hello_retry_request_random));
    // The message must contain a key_share extension naming X25519 (0x001d).
    var found_group = false;
    var i: usize = 0;
    while (i + 1 < n) : (i += 1) {
        if (out[i] == 0x00 and out[i + 1] == 0x1d) found_group = true;
    }
    try testing.expect(found_group);
}

test "handshake: ClientHello with X25519 only in supported_groups (no key_share) is not a parse error" {
    const testing = std.testing;
    // Minimal ClientHello: no key_share extension, supported_groups = {X25519}.
    // Body: legacy_version(2) random(32) sid_len(1)=0 cs_len(2)=2 cs(2) comp(1)=1 comp(1)=0 ext...
    var body: [256]u8 = undefined;
    var p: usize = 0;
    writeU16(body[p..], TLS_LEGACY_VERSION);
    p += 2;
    @memset(body[p .. p + 32], 0x11);
    p += 32; // random
    body[p] = 0;
    p += 1; // session_id len = 0
    writeU16(body[p..], 2);
    p += 2; // cipher_suites len
    writeU16(body[p..], TLS_AES_128_GCM_SHA256);
    p += 2;
    body[p] = 1;
    p += 1; // compression methods len
    body[p] = 0;
    p += 1; // null compression
    // extensions: supported_groups {X25519}
    var ext: [16]u8 = undefined;
    var ep: usize = 0;
    writeU16(ext[ep..], EXT_SUPPORTED_GROUPS);
    ep += 2;
    writeU16(ext[ep..], 4);
    ep += 2; // ext_data len
    writeU16(ext[ep..], 2);
    ep += 2; // group list byte length
    writeU16(ext[ep..], GROUP_X25519);
    ep += 2;
    writeU16(body[p..], @intCast(ep));
    p += 2; // extensions total length
    @memcpy(body[p .. p + ep], ext[0..ep]);
    p += ep;

    var msg: [300]u8 = undefined;
    const total = writeHsMsgHeader(&msg, 0, MSG_CLIENT_HELLO, p);
    @memcpy(msg[total .. total + p], body[0..p]);

    const ch = try parseClientHello(msg[0 .. total + p]);
    try testing.expect(ch.x25519_key == null); // no key_share offered
    try testing.expect(ch.x25519_supported_group); // but X25519 acceptable → HRR path
}

test "handshake: QUIC key derivation" {
    const testing = std.testing;
    const secret = [_]u8{0x77} ** 32;
    const km = deriveQuicKeys(secret);
    // AES-128-GCM keys and IVs should be non-zero
    try testing.expect(!std.mem.allEqual(u8, &km.key, 0));
    try testing.expect(!std.mem.allEqual(u8, &km.iv, 0));
    try testing.expect(!std.mem.allEqual(u8, &km.hp, 0));
    // Key ≠ IV ≠ HP
    try testing.expect(!std.mem.eql(u8, &km.key, &km.hp));
    // ChaCha20-Poly1305 fields should be non-zero
    try testing.expect(!std.mem.allEqual(u8, &km.key32, 0));
    try testing.expect(!std.mem.allEqual(u8, &km.hp32, 0));
    // key32 and hp32 are independently derived with length=32 in HkdfLabel
    // (different from key/hp which use length=16) — just verify they're distinct
    try testing.expect(!std.mem.eql(u8, &km.key32, &km.hp32));
}
