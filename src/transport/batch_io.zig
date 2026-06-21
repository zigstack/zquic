//! Batched UDP send/receive helpers.
//!
//! On Linux we use sendmmsg(2)/recvmmsg(2) to push or pull up to BATCH_SIZE
//! datagrams with a single syscall, cutting per-packet syscall overhead by up
//! to 64×.  On other platforms we fall back to individual sendto/recvfrom
//! calls so the code stays portable for development on macOS.
//!
//! Typical usage (send side):
//!   var batch = SendBatch{};
//!   for (packets_to_send) |pkt| {
//!       if (batch.enqueue(pkt.buf, pkt.addr)) batch.flush(sock);
//!   }
//!   batch.flush(sock);      // flush any remaining
//!
//! Typical usage (recv side):
//!   var rb = RecvBatch{};
//!   const n = rb.recv(sock);
//!   for (rb.entries[0..n]) |*e| processPacket(e.buf[0..e.len], e.addr);

const std = @import("std");
const compat = @import("../compat.zig");
const types = @import("../types.zig");
const builtin = @import("builtin");
const build_options = @import("build_options");
/// Use the Linux `sendmmsg(2)`/`recvmmsg(2)` batched path. Disabled under the
/// Shadow build (#216) — the simulator's shim does not virtualize those calls,
/// so the per-message `sendto`/`recvfrom` portable path is used instead and all
/// I/O routes through Shadow's intercepted libc.
const is_linux_batched = builtin.os.tag == .linux and !build_options.shadow;

/// Platform-safe MSG_DONTWAIT constant (std.posix.MSG is void on some macOS builds).
const MSG_DONTWAIT: u32 = if (@hasDecl(std.posix, "MSG") and @typeInfo(@TypeOf(std.posix.MSG)) == .@"struct")
    MSG_DONTWAIT
else switch (builtin.target.os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => 0x80,
    else => 0x40, // Linux
};

pub const MAX_DATAGRAM_SIZE: usize = types.max_datagram_size;
pub const BATCH_SIZE: usize = 64;

// ── Send batch ────────────────────────────────────────────────────────────────

/// One slot in the send queue.
pub const SendEntry = struct {
    buf: [MAX_DATAGRAM_SIZE]u8 = undefined,
    len: usize = 0,
    addr: compat.Address = undefined,
};

/// Accumulate outgoing UDP datagrams and flush them in a single syscall.
pub const SendBatch = struct {
    entries: [BATCH_SIZE]SendEntry = [_]SendEntry{.{}} ** BATCH_SIZE,
    count: usize = 0,

    /// Enqueue one datagram.  Returns true when the batch is full; the caller
    /// should then call flush() before enqueuing more.
    pub fn enqueue(self: *SendBatch, buf: []const u8, addr: compat.Address) bool {
        if (self.count >= BATCH_SIZE) return true;
        const e = &self.entries[self.count];
        const n = @min(buf.len, MAX_DATAGRAM_SIZE);
        @memcpy(e.buf[0..n], buf[0..n]);
        e.len = n;
        e.addr = addr;
        self.count += 1;
        return self.count >= BATCH_SIZE;
    }

    /// Send all queued datagrams.  On Linux a single sendmmsg(2) call is made;
    /// on other platforms a tight loop of sendto(2) calls is used.
    pub fn flush(self: *SendBatch, sock: std.posix.socket_t) void {
        const cnt = self.count;
        self.count = 0;
        if (cnt == 0) return;

        if (is_linux_batched) {
            flushLinux(sock, self.entries[0..cnt]);
        } else {
            for (self.entries[0..cnt]) |*e| {
                sendOne(sock, e);
            }
        }
    }

    pub fn len(self: *const SendBatch) usize {
        return self.count;
    }
};

/// Process-wide count of datagrams the local kernel refused on send and that
/// this layer could not place on the wire (EWOULDBLOCK/ENOBUFS = SNDBUF full /
/// loopback virtual-link saturated under a bulk catch-up burst, or a hard
/// error). Surfaced in the CC trace: a *local* drop is NOT network congestion —
/// the packet never reached the wire, so the peer never ACKs it and the loss
/// detector reports a spurious loss that needlessly collapses cwnd. Attributing
/// a cwnd collapse to this counter vs real loss is the whole point.
pub var local_send_drops = std.atomic.Value(u64).init(0);

/// `sendto` with a bounded retry. On loopback the SNDBUF drains in microseconds,
/// so a few spins usually clears a transient EWOULDBLOCK and gets the datagram
/// out instead of dropping it (which would later surface as spurious loss and
/// collapse cwnd to the floor without recovering). Counts a drop only if every
/// attempt fails.
fn sendOne(sock: std.posix.socket_t, e: *const SendEntry) void {
    var attempt: u8 = 0;
    while (attempt < 8) : (attempt += 1) {
        if (compat.sendto(sock, e.buf[0..e.len], 0, &e.addr.any, e.addr.getOsSockLen())) |_| {
            return; // on the wire
        } else |_| {
            std.atomic.spinLoopHint();
        }
    }
    _ = local_send_drops.fetchAdd(1, .monotonic);
}

fn flushLinux(sock: std.posix.socket_t, entries: []SendEntry) void {
    const linux = std.os.linux;

    // One iovec per message (each datagram is a single contiguous buffer).
    var iovecs: [BATCH_SIZE]std.posix.iovec_const = undefined;
    // 0.16 dropped the `mmsghdr_const` alias; the layout is identical to
    // `mmsghdr` so we reuse that for the send path.
    var msgs: [BATCH_SIZE]linux.mmsghdr = undefined;

    var sent: usize = 0;
    while (sent < entries.len) {
        const batch_end = @min(sent + BATCH_SIZE, entries.len);
        const batch = entries[sent..batch_end];

        for (batch, 0..) |*e, i| {
            iovecs[i] = .{ .base = e.buf[0..e.len].ptr, .len = e.len };
            msgs[i] = .{
                .hdr = .{
                    .name = @ptrCast(@constCast(&e.addr.any)),
                    .namelen = e.addr.getOsSockLen(),
                    .iov = @ptrCast(&iovecs[i]),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
        }

        // sendmmsg(2) returns the number of messages actually queued.  A
        // previous version ignored the rc and assumed every message went
        // out, which silently dropped the tail on any short send and
        // dropped EVERYTHING on hard errors (EAGAIN, ENOBUFS, EBADF, …).
        // That matches the empirical 24-in / 2-out asymmetry observed on
        // loopback when zeam's server starts emitting STREAM-frame acks.
        // RFC 9000 §13.2 makes server-side STREAM frames discardable on
        // the wire but zquic's PTO does NOT re-arm for arbitrary
        // ack-eliciting raw-app STREAMs, so a dropped batch never
        // retransmits and the libp2p layer above stalls.
        //
        // Fix: check the rc.  On a short return, retry the tail
        // synchronously via sendto.  On error (rc <= 0) fall back to
        // sendto for the whole batch so the syscall path's error gets
        // exercised per-packet (and an individual EAGAIN doesn't drop
        // the rest of the connection's outbound traffic).
        const rc = linux.sendmmsg(@intCast(sock), msgs[0..batch.len].ptr, @intCast(batch.len), 0);
        const rc_i: isize = @bitCast(rc);
        if (rc_i <= 0) {
            for (batch) |*e| {
                sendOne(sock, e);
            }
        } else {
            const n: usize = @intCast(rc_i);
            if (n < batch.len) {
                for (batch[n..]) |*e| {
                    sendOne(sock, e);
                }
            }
        }
        sent += batch.len;
    }
}

// ── Receive batch ─────────────────────────────────────────────────────────────

pub const RecvEntry = struct {
    buf: [MAX_DATAGRAM_SIZE]u8 = undefined,
    len: usize = 0,
    addr: compat.Address = undefined,
};

/// Receive up to BATCH_SIZE UDP datagrams in a single syscall.
pub const RecvBatch = struct {
    entries: [BATCH_SIZE]RecvEntry = [_]RecvEntry{.{}} ** BATCH_SIZE,

    /// Receive as many datagrams as are ready (up to BATCH_SIZE), non-blocking
    /// (MSG_DONTWAIT) for calls after the first.
    /// `blocking_first` — if true, the first message is received with a
    /// blocking call (suitable after poll() indicates data is available).
    /// Returns the number of messages received.
    pub fn recv(self: *RecvBatch, sock: std.posix.socket_t, blocking_first: bool) usize {
        if (is_linux_batched) {
            return recvLinux(self, sock, blocking_first);
        } else {
            return recvPortable(self, sock, blocking_first);
        }
    }
};

fn recvLinux(rb: *RecvBatch, sock: std.posix.socket_t, blocking_first: bool) usize {
    const linux = std.os.linux;

    var iovecs: [BATCH_SIZE]std.posix.iovec = undefined;
    var addrs: [BATCH_SIZE]std.posix.sockaddr.storage = undefined;
    var msgs: [BATCH_SIZE]linux.mmsghdr = undefined;

    for (0..BATCH_SIZE) |i| {
        iovecs[i] = .{ .base = &rb.entries[i].buf, .len = MAX_DATAGRAM_SIZE };
        msgs[i] = .{
            .hdr = .{
                .name = @ptrCast(&addrs[i]),
                .namelen = @sizeOf(std.posix.sockaddr.storage),
                .iov = @ptrCast(&iovecs[i]),
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            },
            .len = 0,
        };
    }

    // MSG_WAITFORONE: block until the FIRST message arrives, then switch to
    // MSG_DONTWAIT for the remaining slots — returning with however many
    // datagrams were already queued in the kernel buffer.  Without this flag,
    // recvmmsg(flags=0) would block until ALL vlen (64) messages are received,
    // which would deadlock the server event loop.
    // When blocking_first=false (pre-poll data already known not to be available)
    // add MSG_DONTWAIT so the call returns immediately if nothing is ready.
    const flags0: u32 = if (blocking_first)
        linux.MSG.WAITFORONE
    else
        linux.MSG.WAITFORONE | linux.MSG.DONTWAIT;
    const rc = linux.recvmmsg(@intCast(sock), msgs[0..].ptr, BATCH_SIZE, flags0, null);
    if (rc == 0 or @as(isize, @bitCast(rc)) < 0) return 0;
    const n: usize = @intCast(rc);

    for (0..n) |i| {
        rb.entries[i].len = msgs[i].len;
        rb.entries[i].addr = .{ .any = @as(*const std.posix.sockaddr, @ptrCast(&addrs[i])).* };
    }
    return n;
}

fn recvPortable(rb: *RecvBatch, sock: std.posix.socket_t, blocking_first: bool) usize {
    var count: usize = 0;
    while (count < BATCH_SIZE) {
        var src_addr: std.posix.sockaddr.storage = undefined;
        var src_len: std.posix.socklen_t = @sizeOf(@TypeOf(src_addr));
        const flags: u32 = if (count == 0 and blocking_first) 0 else MSG_DONTWAIT;
        const n = compat.recvfrom(
            sock,
            &rb.entries[count].buf,
            flags,
            @ptrCast(&src_addr),
            &src_len,
        ) catch |err| {
            if (count > 0 and err == error.WouldBlock) break;
            break;
        };
        rb.entries[count].len = n;
        rb.entries[count].addr = .{ .any = @as(*const std.posix.sockaddr, @ptrCast(&src_addr)).* };
        count += 1;
    }
    return count;
}
