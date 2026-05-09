//! QUIC RFC 9000 §16 varint, sourced from
//! [`zig-varint`](https://github.com/ch4r10t33r/zig-varint).
//!
//! This file is a back-compat re-export so existing call sites keep
//! `@import("varint.zig")` and reference the same symbol names that the old
//! in-tree module exposed (`encode`, `decode`, `lenToUsize`, `Reader`,
//! `Writer`, `EncodeError`, `DecodeError`, `max_value`, `encodedLen`).

const quic = @import("zig_varint").quic;

pub const max_value = quic.max_value;
pub const EncodeError = quic.EncodeError;
pub const DecodeError = quic.DecodeError;

pub const lenToUsize = quic.lenToUsize;
pub const encodedLen = quic.encodedLen;
pub const encode = quic.encode;
pub const decode = quic.decode;

pub const Reader = quic.Reader;
pub const Writer = quic.Writer;

test {
    _ = quic;
}
