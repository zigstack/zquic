//! zquic server — interop runner entry point.
//!
//! Parses the command-line flags produced by interop/run_endpoint.sh and
//! starts a QUIC server that can serve files from /www and run the
//! quic-interop-runner test cases.
//!
//! Supported flags (all optional, with defaults):
//!   --port <n>        UDP port to bind (default 443)
//!   --cert <path>     TLS certificate PEM file (default /certs/cert.pem)
//!   --key  <path>     TLS private key PEM file (default /certs/priv.key)
//!   --www  <dir>      Root directory for file serving (default /www)
//!   --keylog <path>   TLS key log file path
//!   --qlog-dir <dir>  qlog output directory
//!   --http09          Serve HTTP/0.9 requests (for transfer test case)
//!   --http3           Serve HTTP/3 requests
//!   --retry           Send a Retry packet before accepting connections
//!   --resumption      Enable session ticket resumption
//!   --early-data      Enable 0-RTT early data
//!   --migrate         Support connection migration
//!   --rebind          Rebind to a new port after connection established
//!   --key-update      Perform a key update after the handshake
//!   --chacha20        Prefer ChaCha20-Poly1305 cipher suite

const std = @import("std");
const io_mod = @import("zquic").transport.io;

const Config = struct {
    port: u16 = 443,
    cert: []const u8 = "/certs/cert.pem",
    key: []const u8 = "/certs/priv.key",
    www: []const u8 = "/www",
    keylog: ?[]const u8 = null,
    qlog_dir: ?[]const u8 = null,
    // Feature flags
    http09: bool = false,
    http3: bool = false,
    retry: bool = false,
    resumption: bool = false,
    early_data: bool = false,
    migrate: bool = false,
    rebind: bool = false,
    key_update: bool = false,
    chacha20: bool = false,
    v2: bool = false,
};

fn parseArgs(args: []const []const u8) !Config {
    var cfg = Config{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--cert")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.cert = args[i];
        } else if (std.mem.eql(u8, arg, "--key")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.key = args[i];
        } else if (std.mem.eql(u8, arg, "--www")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.www = args[i];
        } else if (std.mem.eql(u8, arg, "--keylog")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.keylog = args[i];
        } else if (std.mem.eql(u8, arg, "--qlog-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.qlog_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--http09")) {
            cfg.http09 = true;
        } else if (std.mem.eql(u8, arg, "--http3")) {
            cfg.http3 = true;
        } else if (std.mem.eql(u8, arg, "--retry")) {
            cfg.retry = true;
        } else if (std.mem.eql(u8, arg, "--resumption")) {
            cfg.resumption = true;
        } else if (std.mem.eql(u8, arg, "--early-data")) {
            cfg.early_data = true;
        } else if (std.mem.eql(u8, arg, "--migrate")) {
            cfg.migrate = true;
        } else if (std.mem.eql(u8, arg, "--rebind")) {
            cfg.rebind = true;
        } else if (std.mem.eql(u8, arg, "--key-update")) {
            cfg.key_update = true;
        } else if (std.mem.eql(u8, arg, "--chacha20")) {
            cfg.chacha20 = true;
        } else if (std.mem.eql(u8, arg, "--v2")) {
            cfg.v2 = true;
        } else {
            std.debug.print("Unknown flag: {s}\n", .{arg});
            return error.UnknownFlag;
        }
    }
    return cfg;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Collect CLI args from the new 0.16 Args iterator into a []const []const u8
    // slice so the existing parseArgs signature does not have to change.
    var arg_it = try std.process.Args.Iterator.initAllocator(init.args, allocator);
    defer arg_it.deinit();
    var args_list: std.ArrayList([]const u8) = .empty;
    defer {
        for (args_list.items) |s| allocator.free(s);
        args_list.deinit(allocator);
    }
    while (arg_it.next()) |a| {
        try args_list.append(allocator, try allocator.dupe(u8, a));
    }
    const args = args_list.items;

    const cfg = parseArgs(args) catch |err| {
        std.debug.print("Argument parse error: {}\n", .{err});
        std.process.exit(1);
    };

    std.debug.print("zquic server starting on port {d} [cert={s}] [www={s}]\n", .{
        cfg.port, cfg.cert, cfg.www,
    });
    if (cfg.retry) std.debug.print("  retry: enabled\n", .{});
    if (cfg.resumption) std.debug.print("  resumption: enabled\n", .{});
    if (cfg.early_data) std.debug.print("  0-RTT: enabled\n", .{});
    if (cfg.http09) std.debug.print("  http/0.9: enabled\n", .{});
    if (cfg.http3) std.debug.print("  http/3: enabled\n", .{});
    if (cfg.key_update) std.debug.print("  key-update: enabled\n", .{});
    if (cfg.migrate) std.debug.print("  migration: enabled\n", .{});
    if (cfg.chacha20) std.debug.print("  chacha20: enabled\n", .{});
    if (cfg.v2) std.debug.print("  QUIC v2: enabled\n", .{});
    if (cfg.qlog_dir) |d| std.debug.print("  qlog-dir: {s}\n", .{d});

    const server_config = io_mod.ServerConfig{
        .port = cfg.port,
        .cert_path = cfg.cert,
        .key_path = cfg.key,
        .www_dir = cfg.www,
        .keylog_path = cfg.keylog,
        .retry_enabled = cfg.retry,
        .resumption_enabled = cfg.resumption,
        .early_data = cfg.early_data,
        .http09 = cfg.http09,
        .http3 = cfg.http3,
        .key_update = cfg.key_update,
        .migrate = cfg.migrate,
        .chacha20 = cfg.chacha20,
        .v2 = cfg.v2,
        .qlog_dir = cfg.qlog_dir,
    };

    const server = io_mod.Server.init(allocator, server_config) catch |err| {
        std.debug.print("server init failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer server.deinit();

    server.run() catch |err| {
        std.debug.print("server run error: {}\n", .{err});
        std.process.exit(1);
    };
}
