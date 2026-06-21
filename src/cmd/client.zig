//! zquic client — interop runner entry point.
//!
//! Parses the command-line flags produced by interop/run_endpoint.sh and
//! downloads files from a QUIC server, writing them to /downloads.
//!
//! Supported flags:
//!   --host <host>     Server hostname or IP
//!   --port <n>        UDP port (default 443)
//!   --url <url>       URL to fetch (can be repeated; max 2048)
//!   --output <dir>    Directory to write downloads (default /downloads)
//!   --keylog <path>   TLS key log file path
//!   --qlog-dir <dir>  qlog output directory
//!   --http09          Use HTTP/0.9 (for transfer test case)
//!   --http3           Use HTTP/3
//!   --chacha20        Prefer ChaCha20-Poly1305 cipher suite
//!   --retry           Expect and handle a Retry packet
//!   --resumption      Attempt session resumption
//!   --early-data      Send 0-RTT early data
//!   --migrate         Migrate connection after establishment
//!   --rebind          Rebind local port mid-connection
//!   --key-update      Request a key update after handshake

const std = @import("std");
const io_mod = @import("zquic").transport.io;

const max_urls: usize = 2048;

const Config = struct {
    host: []const u8 = "localhost",
    port: u16 = 443,
    urls: [max_urls][]const u8 = undefined,
    url_count: usize = 0,
    output: []const u8 = "/downloads",
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
        if (std.mem.eql(u8, arg, "--host")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.host = args[i];
        } else if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--url")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            if (cfg.url_count >= max_urls) return error.TooManyUrls;
            cfg.urls[cfg.url_count] = args[i];
            cfg.url_count += 1;
        } else if (std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.output = args[i];
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

    std.debug.print("zquic client connecting to {s}:{d} (output: {s})\n", .{
        cfg.host, cfg.port, cfg.output,
    });

    const client_config = io_mod.ClientConfig{
        .host = cfg.host,
        .port = cfg.port,
        .output_dir = cfg.output,
        .urls = cfg.urls[0..cfg.url_count],
        .keylog_path = cfg.keylog,
        .resumption = cfg.resumption,
        .early_data = cfg.early_data,
        .key_update = cfg.key_update,
        .http09 = cfg.http09,
        .http3 = cfg.http3,
        .chacha20 = cfg.chacha20,
        .migrate = cfg.migrate,
        .v2 = cfg.v2,
        .qlog_dir = cfg.qlog_dir,
    };

    // `Client` is ~4 MB (ConnState + the new client-side `send_batch` from
    // 72bfda3). `Client.init` returns by value, which the docker interop
    // container's default stack cannot safely accommodate — `client = init(...)`
    // segfaults inside `runEventLoop` shortly after the qlog
    // `connection_started` event. Allocate on the heap via `initInPlace`.
    const client = allocator.create(io_mod.Client) catch |err| {
        std.debug.print("client allocation failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.destroy(client);

    io_mod.Client.initInPlace(allocator, client_config, client) catch |err| {
        std.debug.print("client init failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer client.deinit();

    client.run() catch |err| {
        std.debug.print("client run error: {}\n", .{err});
        std.process.exit(1);
    };
}
