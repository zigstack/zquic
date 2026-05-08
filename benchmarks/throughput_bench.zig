//! End-to-end loopback throughput benchmark.
//!
//! Spawns a zquic server and client on localhost, transfers a large file,
//! and reports MB/s.  Removes the NS3 interop pacing throttle so the
//! congestion controller and crypto path are the actual bottleneck.
//!
//! Usage:
//!   zig build bench-e2e                         # default 50 MB transfer
//!   zig build bench-e2e -- --size-mb 200        # larger transfer
//!   zig build bench-e2e -- --port 14433         # custom port
//!
//! What this measures:
//!   - Full encrypt + send + recv + decrypt round-trip on loopback
//!   - Effect of perf improvements #3 (no debug prints), #4 (O(1) poll),
//!     #5 (64-slot array)
//!   - Compare with a baseline binary built from master (without perf changes)

const std = @import("std");
const fs = std.fs;

const DEFAULT_SIZE_MB: usize = 50;
const DEFAULT_PORT: u16 = 14433;
const CHUNK: usize = 64 * 1024; // 64 KB read buffer

// Temporary paths — all under /tmp so no repo pollution.
const CERT_PATH = "/tmp/zquic_bench_cert.pem";
const KEY_PATH = "/tmp/zquic_bench_key.pem";

/// Generate a self-signed ECDSA cert + key into /tmp if not already present.
/// Uses `openssl` which is available on macOS and most Linux distros.
fn ensureCert() !void {
    // Skip if both files already exist and are non-empty.
    const cert_ok = blk: {
        const f = fs.openFileAbsolute(CERT_PATH, .{}) catch break :blk false;
        defer f.close();
        const st = f.stat() catch break :blk false;
        break :blk st.size > 0;
    };
    const key_ok = blk: {
        const f = fs.openFileAbsolute(KEY_PATH, .{}) catch break :blk false;
        defer f.close();
        const st = f.stat() catch break :blk false;
        break :blk st.size > 0;
    };
    if (cert_ok and key_ok) return;

    std.debug.print("Generating self-signed cert for benchmark...\n", .{});
    const argv = [_][]const u8{
        "openssl",                 "req",
        "-x509",                   "-newkey",
        "ec",                      "-pkeyopt",
        "ec_paramgen_curve:P-256", "-keyout",
        KEY_PATH,                  "-out",
        CERT_PATH,                 "-days",
        "1",                       "-nodes",
        "-subj",                   "/CN=localhost",
    };
    var proc = std.process.Child.init(&argv, std.heap.page_allocator);
    proc.stdout_behavior = .Ignore;
    proc.stderr_behavior = .Ignore;
    const term = try proc.spawnAndWait();
    if (term != .Exited or term.Exited != 0) {
        std.debug.print("ERROR: openssl cert generation failed: {}\n", .{term});
        return error.CertGenFailed;
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Parse args
    var size_mb: usize = DEFAULT_SIZE_MB;
    var port: u16 = DEFAULT_PORT;
    var server_bin: []const u8 = "./zig-out/bin/server";
    var client_bin: []const u8 = "./zig-out/bin/client";

    var args = try std.process.Args.Iterator.initAllocator(init.args, alloc);
    defer args.deinit();
    _ = args.next(); // skip argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--size-mb")) {
            if (args.next()) |v| size_mb = try std.fmt.parseInt(usize, v, 10);
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = try std.fmt.parseInt(u16, v, 10);
        } else if (std.mem.eql(u8, arg, "--server")) {
            if (args.next()) |v| server_bin = v;
        } else if (std.mem.eql(u8, arg, "--client")) {
            if (args.next()) |v| client_bin = v;
        }
    }

    std.debug.print("\n=== zquic end-to-end throughput benchmark ===\n", .{});
    std.debug.print("    file size : {} MB\n", .{size_mb});
    std.debug.print("    port      : {}\n", .{port});
    std.debug.print("    server    : {s}\n", .{server_bin});
    std.debug.print("    client    : {s}\n\n", .{client_bin});

    // Ensure a TLS cert+key exist in /tmp.
    try ensureCert();

    // Create temporary www and download directories.
    const www_dir = "/tmp/zquic_bench_www";
    const dl_dir = "/tmp/zquic_bench_dl";
    fs.makeDirAbsolute(www_dir) catch |e| if (e != error.PathAlreadyExists) return e;
    fs.makeDirAbsolute(dl_dir) catch |e| if (e != error.PathAlreadyExists) return e;

    const test_file = www_dir ++ "/bench.bin";
    const expected_bytes = size_mb * 1024 * 1024;

    // Write test file with random bytes (crypto makes it effectively incompressible).
    {
        std.debug.print("Creating {d} MB test file... ", .{size_mb});
        const f = try fs.createFileAbsolute(test_file, .{});
        defer f.close();
        var buf: [CHUNK]u8 = undefined;
        var written: usize = 0;
        var rng = std.Random.DefaultPrng.init(0xdeadbeef);
        while (written < expected_bytes) {
            const n = @min(CHUNK, expected_bytes - written);
            rng.random().bytes(buf[0..n]);
            try f.writeAll(buf[0..n]);
            written += n;
        }
        std.debug.print("done.\n", .{});
    }

    // Launch server with HTTP/0.9 file serving enabled.
    const port_str = try std.fmt.allocPrint(alloc, "{}", .{port});
    const server_argv = [_][]const u8{
        server_bin,
        "--port",
        port_str,
        "--www",
        www_dir,
        "--cert",
        CERT_PATH,
        "--key",
        KEY_PATH,
        "--http09",
    };
    std.debug.print("Launching server on :{d}...\n", .{port});
    var server_proc = std.process.Child.init(&server_argv, alloc);
    server_proc.stdout_behavior = .Ignore;
    server_proc.stderr_behavior = .Ignore;
    try server_proc.spawn();

    // Give the server a moment to bind its UDP socket.
    std.Thread.sleep(300 * std.time.ns_per_ms);

    // Launch client and time the download.
    // URL path is /bench.bin; client saves to {dl_dir}/bench.bin.
    const dl_file = try std.fmt.allocPrint(alloc, "{s}/bench.bin", .{dl_dir});
    const url = try std.fmt.allocPrint(alloc, "https://localhost:{d}/bench.bin", .{port});
    const client_argv = [_][]const u8{
        client_bin,
        "--host",
        "localhost",
        "--port",
        port_str,
        "--url",    url, // singular --url, not --urls
        "--output", dl_dir,
        "--http09", // must match server mode
    };
    std.debug.print("Downloading {s}...\n", .{url});

    var timer = try std.time.Timer.start();
    var client_proc = std.process.Child.init(&client_argv, alloc);
    client_proc.stdout_behavior = .Ignore;
    client_proc.stderr_behavior = .Ignore;
    try client_proc.spawn();
    const term = try client_proc.wait();
    const elapsed_ns = timer.read();

    // Kill server.
    _ = server_proc.kill() catch {};
    _ = server_proc.wait() catch {};

    // Verify download size.
    const stat = fs.openFileAbsolute(dl_file, .{}) catch |e| {
        std.debug.print("ERROR: could not open downloaded file {s}: {}\n", .{ dl_file, e });
        std.debug.print("       client exit: {}\n", .{term});
        // Cleanup best-effort then fail.
        fs.deleteFileAbsolute(test_file) catch {};
        return error.DownloadFileMissing;
    };
    defer stat.close();
    const info = try stat.stat();
    const recv_bytes = info.size;

    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1e9;
    const mb_transferred = @as(f64, @floatFromInt(recv_bytes)) / (1024.0 * 1024.0);
    const throughput_mbs = mb_transferred / elapsed_s;
    const throughput_mbits = throughput_mbs * 8.0;

    const complete = recv_bytes == expected_bytes;
    std.debug.print("\n--- Results ---\n", .{});
    std.debug.print("  exit code       : {}\n", .{term});
    std.debug.print("  bytes received  : {d} / {d}  ({s})\n", .{
        recv_bytes,
        expected_bytes,
        if (complete) "✓ complete" else "✗ incomplete",
    });
    std.debug.print("  elapsed         : {d} ms\n", .{elapsed_ms});
    std.debug.print("  throughput      : {d:.1} MB/s  ({d:.1} Mbps)\n", .{ throughput_mbs, throughput_mbits });

    // Cleanup.
    fs.deleteFileAbsolute(test_file) catch {};
    fs.deleteFileAbsolute(dl_file) catch {};

    if (!complete) {
        std.debug.print("FAIL: transfer incomplete ({d} of {d} bytes)\n", .{ recv_bytes, expected_bytes });
        return error.TransferIncomplete;
    }
}
