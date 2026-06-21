//! Connection statistics helpers (RFC 9000 frame accounting + snapshots).

const std = @import("std");
const varint = @import("../varint.zig");
const connection_mod = @import("connection.zig");

pub const FrameStats = connection_mod.FrameStats;
pub const StatsAccumulator = connection_mod.StatsAccumulator;

pub fn noteDatagramRx(acc: *StatsAccumulator, len: usize) void {
    acc.udp.datagrams_rx += 1;
    acc.udp.bytes_rx += @intCast(len);
}

pub fn noteDatagramTx(acc: *StatsAccumulator, len: usize) void {
    acc.udp.datagrams_tx += 1;
    acc.udp.bytes_tx += @intCast(len);
}

pub fn noteFrameRx(frames: *FrameStats, ft: u64) void {
    switch (ft) {
        0x01 => frames.ping_rx += 1,
        0x02, 0x03 => frames.ack_rx += 1,
        0x04 => frames.reset_stream_rx += 1,
        0x05 => frames.stop_sending_rx += 1,
        0x06 => frames.crypto_rx += 1,
        0x07 => frames.new_token_rx += 1,
        0x08...0x0f => frames.stream_rx += 1,
        0x10 => frames.max_data_rx += 1,
        0x11 => frames.max_stream_data_rx += 1,
        0x12 => frames.max_streams_rx += 1,
        0x13 => frames.data_blocked_rx += 1,
        0x14 => frames.data_blocked_rx += 1,
        0x15 => frames.stream_data_blocked_rx += 1,
        0x16, 0x17 => frames.streams_blocked_rx += 1,
        0x18 => frames.new_connection_id_rx += 1,
        0x19 => frames.retire_connection_id_rx += 1,
        0x1a => frames.path_challenge_rx += 1,
        0x1b => frames.path_response_rx += 1,
        0x1c, 0x1d => frames.connection_close_rx += 1,
        0x1e => frames.handshake_done_rx += 1,
        else => {},
    }
}

pub fn noteFrameTx(frames: *FrameStats, ft: u64) void {
    switch (ft) {
        0x01 => frames.ping_tx += 1,
        0x02, 0x03 => frames.ack_tx += 1,
        0x04 => frames.reset_stream_tx += 1,
        0x05 => frames.stop_sending_tx += 1,
        0x06 => frames.crypto_tx += 1,
        0x07 => frames.new_token_tx += 1,
        0x08...0x0f => frames.stream_tx += 1,
        0x10 => frames.max_data_tx += 1,
        0x11 => frames.max_stream_data_tx += 1,
        0x12 => frames.max_streams_tx += 1,
        0x13 => frames.data_blocked_tx += 1,
        0x14 => frames.data_blocked_tx += 1,
        0x15 => frames.stream_data_blocked_tx += 1,
        0x16, 0x17 => frames.streams_blocked_tx += 1,
        0x18 => frames.new_connection_id_tx += 1,
        0x19 => frames.retire_connection_id_tx += 1,
        0x1a => frames.path_challenge_tx += 1,
        0x1b => frames.path_response_tx += 1,
        0x1c, 0x1d => frames.connection_close_tx += 1,
        0x1e => frames.handshake_done_tx += 1,
        else => {},
    }
}

fn skipFrameBody(ft: u64, buf: []const u8) usize {
    if (buf.len == 0) return 0;
    if (ft == 0x00 or ft == 0x01) return 0;
    if (ft == 0x02 or ft == 0x03) {
        return skipAckBody(buf, ft == 0x03);
    }
    if (ft >= 0x08 and ft <= 0x0f) {
        var pos: usize = 0;
        const sid_r = varint.decode(buf[pos..]) catch return buf.len;
        pos += sid_r.len;
        if ((ft & 0x04) != 0) {
            const off_r = varint.decode(buf[pos..]) catch return buf.len;
            pos += off_r.len;
        }
        if ((ft & 0x02) != 0) {
            const len_r = varint.decode(buf[pos..]) catch return buf.len;
            pos += len_r.len;
            const dlen = varint.lenToUsize(len_r.value) catch return buf.len;
            pos += dlen;
        }
        return pos;
    }
    if (ft == 0x06) {
        var pos: usize = 0;
        const off_r = varint.decode(buf[pos..]) catch return buf.len;
        pos += off_r.len;
        const len_r = varint.decode(buf[pos..]) catch return buf.len;
        pos += len_r.len;
        const dlen = varint.lenToUsize(len_r.value) catch return buf.len;
        return pos + dlen;
    }
    if (ft == 0x07) {
        var pos: usize = 0;
        const len_r = varint.decode(buf[pos..]) catch return buf.len;
        pos += len_r.len;
        const tlen = varint.lenToUsize(len_r.value) catch return buf.len;
        return pos + tlen;
    }
    if (ft == 0x10 or ft == 0x12 or ft == 0x13 or ft == 0x14 or ft == 0x16 or ft == 0x17 or ft == 0x19) {
        const v = varint.decode(buf) catch return buf.len;
        return v.len;
    }
    if (ft == 0x11 or ft == 0x15) {
        var pos: usize = 0;
        const a = varint.decode(buf[pos..]) catch return buf.len;
        pos += a.len;
        const b = varint.decode(buf[pos..]) catch return buf.len;
        return pos + b.len;
    }
    if (ft == 0x04 or ft == 0x05) {
        var pos: usize = 0;
        const a = varint.decode(buf[pos..]) catch return buf.len;
        pos += a.len;
        const b = varint.decode(buf[pos..]) catch return buf.len;
        pos += b.len;
        const c = varint.decode(buf[pos..]) catch return buf.len;
        return pos + c.len;
    }
    if (ft == 0x18) {
        var pos: usize = 0;
        const seq = varint.decode(buf[pos..]) catch return buf.len;
        pos += seq.len;
        const rpt = varint.decode(buf[pos..]) catch return buf.len;
        pos += rpt.len;
        if (pos >= buf.len) return buf.len;
        const cid_len: usize = buf[pos];
        return pos + 1 + cid_len + 16;
    }
    if (ft == 0x1a or ft == 0x1b) return 8;
    if (ft == 0x1e) return 0;
    return buf.len;
}

fn skipAckBody(buf: []const u8, ecn: bool) usize {
    var pos: usize = 0;
    const lar = varint.decode(buf[pos..]) catch return buf.len;
    pos += lar.len;
    const del = varint.decode(buf[pos..]) catch return buf.len;
    pos += del.len;
    const cnt = varint.decode(buf[pos..]) catch return buf.len;
    pos += cnt.len;
    const fst = varint.decode(buf[pos..]) catch return buf.len;
    pos += fst.len;
    var i: u64 = 0;
    while (i < cnt.value) : (i += 1) {
        const gap = varint.decode(buf[pos..]) catch return buf.len;
        pos += gap.len;
        const len = varint.decode(buf[pos..]) catch return buf.len;
        pos += len.len;
    }
    if (ecn) {
        const a = varint.decode(buf[pos..]) catch return buf.len;
        pos += a.len;
        const b = varint.decode(buf[pos..]) catch return buf.len;
        pos += b.len;
        const c = varint.decode(buf[pos..]) catch return buf.len;
        pos += c.len;
    }
    return pos;
}

/// Walk a coalesced 1-RTT payload and bump frame tx counters.
pub fn noteFramesInPayload(frames: *FrameStats, payload: []const u8) void {
    var pos: usize = 0;
    while (pos < payload.len) {
        const ft_r = varint.decode(payload[pos..]) catch break;
        noteFrameTx(frames, ft_r.value);
        pos += ft_r.len;
        pos += skipFrameBody(ft_r.value, payload[pos..]);
    }
}

test "stats: frame walk counts stream and ack" {
    const testing = std.testing;
    var frames: FrameStats = .{};
    var buf: [32]u8 = undefined;
    var w = varint.Writer.init(&buf);
    try w.writeVarint(0x08);
    try w.writeVarint(4);
    try w.writeVarint(0);
    try w.writeBytes("abcd");
    noteFramesInPayload(&frames, buf[0..w.pos]);
    try testing.expectEqual(@as(u64, 1), frames.stream_tx);
    try testing.expectEqual(@as(u64, 0), frames.ack_tx);
}
