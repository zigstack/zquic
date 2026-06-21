//! Compatibility shims for the zig 0.15 → 0.16 standard library reorg.
//!
//! Zig 0.16 removed many high-level wrappers from `std.posix` (socket, bind,
//! sendto, recvfrom, close, open, write, lseek, fstat, mkdir, etc.) and
//! deleted `std.net` and most of `std.fs` outright; these features were moved
//! into the new `std.Io` abstraction.  zquic owns its own UDP event loop and
//! does not need the `std.Io` async machinery — it just needs the raw
//! syscalls back.  This module reinstates a thin posix-style API by calling
//! `std.posix.system.<name>` (= `std.c.<name>` on libc targets) directly.
//!
//! All wrappers translate libc errno into Zig error sets so the rest of the
//! codebase keeps using `try`/`catch` exactly as before.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const system = posix.system;

// ── Errno helper ────────────────────────────────────────────────────────────

inline fn checkRc(rc: anytype) std.posix.E {
    return posix.errno(rc);
}

// ── socket / bind / connect / send / recv ───────────────────────────────────

pub const SocketError = error{
    AccessDenied,
    AddressFamilyUnsupported,
    ProtocolUnsupportedBySystem,
    ProtocolFamilyUnavailable,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
} || posix.UnexpectedError;

pub fn socket(domain: u32, sock_type: u32, protocol: u32) SocketError!posix.socket_t {
    const rc = system.socket(domain, sock_type, protocol);
    switch (checkRc(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .INVAL => return error.ProtocolFamilyUnavailable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .PROTONOSUPPORT => return error.ProtocolUnsupportedBySystem,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const BindError = error{
    AccessDenied,
    AddressInUse,
    AddressNotAvailable,
    AlreadyBound,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    NotDir,
    SystemResources,
} || posix.UnexpectedError;

pub fn bind(sock: posix.socket_t, addr: *const posix.sockaddr, len: posix.socklen_t) BindError!void {
    const rc = system.bind(sock, addr, len);
    switch (checkRc(rc)) {
        .SUCCESS => return,
        .ACCES => return error.AccessDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .INVAL => return error.AlreadyBound,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const ConnectError = error{
    AccessDenied,
    AddressInUse,
    AddressNotAvailable,
    NetworkUnreachable,
    HostUnreachable,
    Timeout,
    ConnectionRefused,
    ConnectionResetByPeer,
    SystemResources,
    AlreadyConnected,
    WouldBlock,
} || posix.UnexpectedError;

pub fn connect(sock: posix.socket_t, addr: *const posix.sockaddr, len: posix.socklen_t) ConnectError!void {
    const rc = system.connect(sock, addr, len);
    switch (checkRc(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.AccessDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .AGAIN, .INPROGRESS => return error.WouldBlock,
        .ALREADY, .ISCONN => return error.AlreadyConnected,
        .CONNREFUSED => return error.ConnectionRefused,
        .CONNRESET => return error.ConnectionResetByPeer,
        .HOSTUNREACH => return error.HostUnreachable,
        .NETUNREACH => return error.NetworkUnreachable,
        .TIMEDOUT => return error.Timeout,
        .NOMEM, .NOBUFS => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const SendToError = error{
    AccessDenied,
    WouldBlock,
    BrokenPipe,
    MessageTooBig,
    ConnectionResetByPeer,
    NetworkUnreachable,
    NetworkDown,
    HostUnreachable,
    SystemResources,
    SocketUnconnected,
    AddressFamilyUnsupported,
} || posix.UnexpectedError;

pub fn sendto(
    sock: posix.socket_t,
    buf: []const u8,
    flags: u32,
    dest_addr: ?*const posix.sockaddr,
    addrlen: posix.socklen_t,
) SendToError!usize {
    while (true) {
        const rc = system.sendto(sock, buf.ptr, buf.len, flags, dest_addr, addrlen);
        switch (checkRc(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .ACCES => return error.AccessDenied,
            .AGAIN => return error.WouldBlock,
            .PIPE => return error.BrokenPipe,
            .MSGSIZE => return error.MessageTooBig,
            .CONNRESET => return error.ConnectionResetByPeer,
            .NETUNREACH => return error.NetworkUnreachable,
            .NETDOWN => return error.NetworkDown,
            .HOSTUNREACH => return error.HostUnreachable,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketUnconnected,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub const RecvFromError = error{
    WouldBlock,
    SystemResources,
    ConnectionResetByPeer,
    ConnectionRefused,
    SocketUnconnected,
} || posix.UnexpectedError;

pub fn recvfrom(
    sock: posix.socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*posix.sockaddr,
    addrlen: ?*posix.socklen_t,
) RecvFromError!usize {
    while (true) {
        const rc = system.recvfrom(sock, buf.ptr, buf.len, flags, src_addr, addrlen);
        switch (checkRc(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET => return error.ConnectionResetByPeer,
            .CONNREFUSED => return error.ConnectionRefused,
            .NOTCONN => return error.SocketUnconnected,
            .NOMEM, .NOBUFS => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub fn close(sock: posix.socket_t) void {
    _ = system.close(sock);
}

// ── CSPRNG ──────────────────────────────────────────────────────────────────
//
// Replaces `std.crypto.random` (removed in 0.16).  Backed by
// `getrandom(2)` on Linux and `getentropy(3)` elsewhere via libc.

fn osRandomBytes(buf: []u8) void {
    // Raw kernel `getrandom(2)` is used only on no-libc Linux (default zquic
    // build). When libc is linked — Darwin, or Linux with `-Dshadow=true` —
    // route through libc so the Shadow simulator's shim can intercept and
    // produce deterministic randomness. See #216.
    if (comptime builtin.os.tag == .linux and !builtin.link_libc) {
        // getrandom(2) is the kernel's CSPRNG; never blocks once seeded.
        // Raw syscall — no libc dependency.
        var off: usize = 0;
        while (off < buf.len) {
            const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
            const e = std.posix.errno(rc);
            if (e == .SUCCESS) {
                off += @intCast(rc);
            } else if (e == .INTR) {
                continue;
            } else {
                @panic("getrandom failed");
            }
        }
    } else if (comptime builtin.os.tag == .linux) {
        // Linux with libc linked (Shadow build) — use libc `getrandom(3)`,
        // which the Shadow shim intercepts.
        var off: usize = 0;
        while (off < buf.len) {
            const n = std.c.getrandom(buf.ptr + off, buf.len - off, 0);
            if (n > 0) {
                off += @intCast(n);
            } else {
                const e = std.posix.errno(n);
                if (e == .INTR) continue;
                @panic("getrandom failed");
            }
        }
    } else {
        // Darwin (and other libc-linked targets) — `arc4random_buf` is always
        // available, never fails, and is the recommended CSPRNG on macOS.
        std.c.arc4random_buf(buf.ptr, buf.len);
    }
}

const RandomSrc = struct {
    fn fill(_: *const RandomSrc, buf: []u8) void {
        osRandomBytes(buf);
    }
};

var random_src: RandomSrc = .{};

/// Drop-in for the removed `std.crypto.random`.  Backed by the OS CSPRNG.
pub const random: std.Random = std.Random.init(&random_src, RandomSrc.fill);

// ── Wall-clock helpers ──────────────────────────────────────────────────────
//
// `std.time.milliTimestamp` was removed in 0.16; the replacement
// (`Io.Timestamp`) requires an `Io` instance.  zquic only needs a coarse
// timestamp for idle timers and RTT estimation, so we call clock_gettime
// directly: a raw kernel syscall on Linux (no libc), libc on Darwin (no
// stable syscall ABI).

/// Returns the current wall-clock time in nanoseconds since the Unix epoch.
///
/// Linux without libc takes the raw `clock_gettime(2)` syscall. Linux with
/// libc (Darwin, or `-Dshadow=true`) goes through libc — required so the
/// Shadow simulator's shim can virtualize simulated time (#216).
pub fn nanoTimestamp() i128 {
    if (comptime builtin.os.tag == .linux and !builtin.link_libc) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
    } else {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.REALTIME, &ts);
        return @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
    }
}

/// Returns the current wall-clock time in milliseconds since the Unix epoch.
pub fn milliTimestamp() i64 {
    return @intCast(@divTrunc(nanoTimestamp(), std.time.ns_per_ms));
}

// ── Address shim ────────────────────────────────────────────────────────────
//
// Mirrors the pre-0.16 `std.net.Address` ergonomics that zquic relies on:
// extern union over sockaddr/sockaddr_in/sockaddr_in6 with `.any`,
// `.getOsSockLen()`, `.getPort()`, `.setPort()`, `.parseIp4()`, `.eql()`.

pub const Address = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,

    pub fn initIp4(addr: [4]u8, port: u16) Address {
        return .{ .in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = @bitCast(addr),
            .zero = [_]u8{0} ** 8,
        } };
    }

    pub fn parseIp4(buf: []const u8, port: u16) !Address {
        var bytes: [4]u8 = undefined;
        var idx: usize = 0;
        var byte: u16 = 0;
        var has_digit = false;
        for (buf) |c| {
            if (c == '.') {
                if (!has_digit or idx >= 3) return error.InvalidIPAddressFormat;
                bytes[idx] = @intCast(byte);
                idx += 1;
                byte = 0;
                has_digit = false;
            } else if (c >= '0' and c <= '9') {
                byte = byte * 10 + (c - '0');
                if (byte > 255) return error.InvalidIPAddressFormat;
                has_digit = true;
            } else {
                return error.InvalidIPAddressFormat;
            }
        }
        if (!has_digit or idx != 3) return error.InvalidIPAddressFormat;
        bytes[3] = @intCast(byte);
        return initIp4(bytes, port);
    }

    pub fn parseIp(buf: []const u8, port: u16) !Address {
        return parseIp4(buf, port);
    }

    pub fn getPort(self: Address) u16 {
        return switch (self.any.family) {
            posix.AF.INET => std.mem.bigToNative(u16, self.in.port),
            posix.AF.INET6 => std.mem.bigToNative(u16, self.in6.port),
            else => 0,
        };
    }

    pub fn setPort(self: *Address, port: u16) void {
        switch (self.any.family) {
            posix.AF.INET => self.in.port = std.mem.nativeToBig(u16, port),
            posix.AF.INET6 => self.in6.port = std.mem.nativeToBig(u16, port),
            else => {},
        }
    }

    pub fn getOsSockLen(self: Address) posix.socklen_t {
        return switch (self.any.family) {
            posix.AF.INET => @sizeOf(posix.sockaddr.in),
            posix.AF.INET6 => @sizeOf(posix.sockaddr.in6),
            else => 0,
        };
    }

    pub fn eql(a: Address, b: Address) bool {
        if (a.any.family != b.any.family) return false;
        return switch (a.any.family) {
            posix.AF.INET => a.in.port == b.in.port and a.in.addr == b.in.addr,
            posix.AF.INET6 => blk: {
                if (a.in6.port != b.in6.port) break :blk false;
                if (!std.mem.eql(u8, &a.in6.addr, &b.in6.addr)) break :blk false;
                break :blk true;
            },
            else => false,
        };
    }
};

// ── DNS resolver shim ───────────────────────────────────────────────────────
//
// Tiny libc `getaddrinfo` wrapper matching the parts of the old
// `std.net.AddressList` API zquic uses (an `addrs: []Address` slice with a
// `.deinit()` method).

pub const AddressList = struct {
    arena: std.heap.ArenaAllocator,
    addrs: []Address,

    pub fn deinit(self: *AddressList) void {
        var arena = self.arena;
        arena.deinit();
    }
};

/// Resolve `host` → list of `Address`.  Pure-Zig path: tries the IP literal
/// parser first, then `/etc/hosts`, then (when libc is linked, i.e. Darwin)
/// falls back to `getaddrinfo` for full DNS.  On Linux without libc, only
/// IP literals and `/etc/hosts` entries resolve — that covers loopback,
/// "localhost", and the interop runner's docker-network names which are
/// always written to `/etc/hosts` inside the test containers.
pub fn getAddressList(allocator: std.mem.Allocator, host: []const u8, port: u16) !AddressList {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var list: std.ArrayList(Address) = .empty;

    // 1. IP literal — handles "127.0.0.1", "192.168.1.1", etc.
    if (Address.parseIp4(host, port)) |ip| {
        try list.append(a, ip);
        return .{ .arena = arena, .addrs = list.items };
    } else |_| {}

    // 2. /etc/hosts lookup.
    if (resolveFromHostsFile(a, host, port)) |found| {
        if (found) |addr| {
            try list.append(a, addr);
            return .{ .arena = arena, .addrs = list.items };
        }
    } else |_| {}

    // 3. libc getaddrinfo — Darwin only (where libc is mandatory).  On
    //    Linux without libc we restrict resolution to IP literals and
    //    /etc/hosts to keep the build pure-Zig.
    if (comptime builtin.link_libc and builtin.os.tag != .linux) {
        const host_c = try a.dupeZ(u8, host);
        var port_buf: [8]u8 = undefined;
        const port_str = try std.fmt.bufPrintZ(&port_buf, "{d}", .{port});

        var hints: std.c.addrinfo = std.mem.zeroes(std.c.addrinfo);
        hints.family = posix.AF.UNSPEC;
        hints.socktype = posix.SOCK.DGRAM;

        var result: ?*std.c.addrinfo = null;
        const rc = std.c.getaddrinfo(host_c.ptr, port_str.ptr, &hints, &result);
        if (rc != @as(@TypeOf(rc), @enumFromInt(0))) return error.UnknownHostName;
        const head = result orelse return error.UnknownHostName;
        defer std.c.freeaddrinfo(head);

        var it: ?*std.c.addrinfo = result;
        while (it) |info| : (it = info.next) {
            const sa = info.addr orelse continue;
            switch (sa.family) {
                posix.AF.INET => {
                    const in_ptr: *const posix.sockaddr.in = @ptrCast(@alignCast(sa));
                    try list.append(a, Address{ .in = in_ptr.* });
                },
                posix.AF.INET6 => {
                    const in6_ptr: *const posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
                    try list.append(a, Address{ .in6 = in6_ptr.* });
                },
                else => {},
            }
        }
        if (list.items.len > 0) {
            return .{ .arena = arena, .addrs = list.items };
        }
    }

    return error.UnknownHostName;
}

/// Open `/etc/hosts` and return the first `Address` whose hostname column
/// (or any of its aliases) matches `name` exactly.  Returns `null` when the
/// file is missing or no match is found.
fn resolveFromHostsFile(a: std.mem.Allocator, name: []const u8, port: u16) !?Address {
    const file = fs.openFileAbsolute("/etc/hosts", .{}) catch return null;
    defer file.close();
    const max_hosts_size: usize = 1 << 20; // 1 MiB
    const contents = file.readToEndAlloc(a, max_hosts_size) catch return null;
    defer a.free(contents);

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw_line| {
        // Strip comments (everything from first '#').
        const line = if (std.mem.indexOfScalar(u8, raw_line, '#')) |i| raw_line[0..i] else raw_line;
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const ip_str = fields.next() orelse continue;
        const addr = Address.parseIp4(ip_str, port) catch continue;
        while (fields.next()) |alias| {
            if (std.mem.eql(u8, alias, name)) return addr;
        }
    }
    return null;
}

// ── fs shim ─────────────────────────────────────────────────────────────────
//
// Replaces the absolute-path file helpers and the small `File` type.  Backed
// by `posix.system.open/read/write/close/lseek/fstat/mkdir`.

pub const fs = struct {
    pub const File = struct {
        handle: posix.fd_t,

        pub const ReadError = error{ ReadFailed, IsDir, NotOpenForReading } || posix.UnexpectedError;
        pub const WriteError = error{ WriteFailed, BrokenPipe, NoSpaceLeft, NotOpenForWriting } || posix.UnexpectedError;

        pub fn close(self: File) void {
            _ = system.close(self.handle);
        }

        pub fn read(self: File, buf: []u8) ReadError!usize {
            while (true) {
                const rc = system.read(self.handle, buf.ptr, buf.len);
                switch (checkRc(rc)) {
                    .SUCCESS => return @intCast(rc),
                    .INTR => continue,
                    .ISDIR => return error.IsDir,
                    .BADF => return error.NotOpenForReading,
                    else => |err| return posix.unexpectedErrno(err),
                }
            }
        }

        pub fn readAll(self: File, buf: []u8) ReadError!usize {
            var total: usize = 0;
            while (total < buf.len) {
                const n = try self.read(buf[total..]);
                if (n == 0) break;
                total += n;
            }
            return total;
        }

        pub fn write(self: File, bytes: []const u8) WriteError!usize {
            while (true) {
                const rc = system.write(self.handle, bytes.ptr, bytes.len);
                switch (checkRc(rc)) {
                    .SUCCESS => return @intCast(rc),
                    .INTR => continue,
                    .PIPE => return error.BrokenPipe,
                    .NOSPC => return error.NoSpaceLeft,
                    .BADF => return error.NotOpenForWriting,
                    else => |err| return posix.unexpectedErrno(err),
                }
            }
        }

        pub fn writeAll(self: File, bytes: []const u8) WriteError!void {
            var i: usize = 0;
            while (i < bytes.len) {
                i += try self.write(bytes[i..]);
            }
        }

        pub const SeekError = error{Unseekable} || posix.UnexpectedError;

        pub fn seekTo(self: File, offset: u64) SeekError!void {
            const rc = system.lseek(self.handle, @intCast(offset), 0); // SEEK_SET
            switch (checkRc(rc)) {
                .SUCCESS => return,
                .SPIPE, .NXIO => return error.Unseekable,
                else => |err| return posix.unexpectedErrno(err),
            }
        }

        pub fn seekFromEnd(self: File, offset: i64) SeekError!void {
            const rc = system.lseek(self.handle, offset, 2); // SEEK_END
            switch (checkRc(rc)) {
                .SUCCESS => return,
                .SPIPE, .NXIO => return error.Unseekable,
                else => |err| return posix.unexpectedErrno(err),
            }
        }

        pub fn getEndPos(self: File) !u64 {
            // Use lseek(fd, 0, SEEK_END) to obtain file size without
            // needing the platform-specific Stat type — `system.fstat` is
            // `{}` on Linux+libc in zig 0.16, which would not compile.
            const end = system.lseek(self.handle, 0, 2); // SEEK_END
            switch (checkRc(end)) {
                .SUCCESS => {},
                else => |err| return posix.unexpectedErrno(err),
            }
            // Restore position so callers that read the file after asking
            // for size are not surprised.
            _ = system.lseek(self.handle, 0, 0); // SEEK_SET
            return @intCast(end);
        }

        pub fn readToEndAlloc(self: File, allocator: std.mem.Allocator, max_bytes: usize) ![]u8 {
            const end = try self.getEndPos();
            if (end > max_bytes) return error.FileTooBig;
            const buf = try allocator.alloc(u8, @intCast(end));
            errdefer allocator.free(buf);
            const n = try self.readAll(buf);
            return buf[0..n];
        }
    };

    pub const OpenFlags = struct {
        mode: enum { read_only, write_only, read_write } = .read_only,
    };

    pub const CreateFlags = struct {
        truncate: bool = true,
        read: bool = false,
        exclusive: bool = false,
        mode: posix.mode_t = 0o644,
    };

    fn openZ(path: [*:0]const u8, flags: posix.O, mode: posix.mode_t) !posix.fd_t {
        while (true) {
            const rc = system.open(path, flags, mode);
            switch (checkRc(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR => continue,
                .ACCES => return error.AccessDenied,
                .NOENT => return error.FileNotFound,
                .EXIST => return error.PathAlreadyExists,
                .ISDIR => return error.IsDir,
                .NOTDIR => return error.NotDir,
                .NAMETOOLONG => return error.NameTooLong,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NFILE => return error.SystemFdQuotaExceeded,
                .NOSPC => return error.NoSpaceLeft,
                .NOMEM => return error.SystemResources,
                else => |err| return posix.unexpectedErrno(err),
            }
        }
    }

    fn nullTerminate(path: []const u8, buf: *[4096]u8) ![*:0]const u8 {
        if (path.len >= buf.len) return error.NameTooLong;
        @memcpy(buf[0..path.len], path);
        buf[path.len] = 0;
        return @ptrCast(buf);
    }

    pub fn openFileAbsolute(path: []const u8, flags: OpenFlags) !File {
        var path_buf: [4096]u8 = undefined;
        const c_path = try nullTerminate(path, &path_buf);
        const access: posix.ACCMODE = switch (flags.mode) {
            .read_only => .RDONLY,
            .write_only => .WRONLY,
            .read_write => .RDWR,
        };
        const fd = try openZ(c_path, .{ .ACCMODE = access }, 0);
        return .{ .handle = fd };
    }

    pub fn createFileAbsolute(path: []const u8, flags: CreateFlags) !File {
        var path_buf: [4096]u8 = undefined;
        const c_path = try nullTerminate(path, &path_buf);
        const oflag: posix.O = .{
            .ACCMODE = if (flags.read) .RDWR else .WRONLY,
            .CREAT = true,
            .TRUNC = flags.truncate,
            .EXCL = flags.exclusive,
        };
        const fd = try openZ(c_path, oflag, flags.mode);
        return .{ .handle = fd };
    }

    pub fn deleteFileAbsolute(path: []const u8) !void {
        var path_buf: [4096]u8 = undefined;
        const c_path = try nullTerminate(path, &path_buf);
        const rc = system.unlink(c_path);
        switch (checkRc(rc)) {
            .SUCCESS => return,
            .NOENT => return error.FileNotFound,
            .ACCES => return error.AccessDenied,
            .ISDIR => return error.IsDir,
            .NAMETOOLONG => return error.NameTooLong,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    pub fn makeDirAbsolute(path: []const u8) !void {
        var path_buf: [4096]u8 = undefined;
        if (path.len >= path_buf.len) return error.NameTooLong;
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;
        const c_path: [*:0]const u8 = @ptrCast(&path_buf);
        const rc = system.mkdir(c_path, 0o755);
        switch (checkRc(rc)) {
            .SUCCESS => return,
            .EXIST => return,
            .ACCES => return error.AccessDenied,
            .NOENT => return error.FileNotFound,
            .NOSPC => return error.NoSpaceLeft,
            .NOTDIR => return error.NotDir,
            .NAMETOOLONG => return error.NameTooLong,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
};
