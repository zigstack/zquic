const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const verbose = b.option(bool, "verbose", "Enable verbose debug output") orelse false;
    // Shadow simulator (https://shadow.github.io) intercepts at the libc layer
    // via LD_PRELOAD; it cannot inject into the default pure-Zig Linux build
    // which uses raw `std.os.linux.*` syscalls and links no libc. When
    // -Dshadow=true, force libc linkage on Linux so `compat.zig` routes time /
    // random / network calls through libc, and disable the `sendmmsg(2)` /
    // `recvmmsg(2)` batched-I/O path (Shadow's shim only handles single-syscall
    // I/O). See `docs/shadow.md` and #216.
    const shadow = b.option(bool, "shadow", "Build for the Shadow network simulator (forces libc on Linux, disables batched I/O)") orelse false;

    // src/compat.zig restores the std-library bits that 0.16 deleted by
    // dispatching directly to raw syscalls on Linux (no libc) and to libc on
    // Darwin (where there is no stable kernel ABI).  Apple platforms must
    // therefore link libc; Linux deliberately does not, keeping zquic a
    // pure-Zig binary on that target. The `-Dshadow=true` build flag overrides
    // the Linux branch to link libc (Shadow's shim requires it).
    const tag = target.result.os.tag;
    const needs_libc: bool = switch (tag) {
        .macos, .ios, .tvos, .watchos, .visionos, .driverkit => true,
        .linux => shadow,
        else => false,
    };

    // Build-options module (verbose flag accessible as @import("build_options").verbose)
    const opts = b.addOptions();
    opts.addOption(bool, "verbose", verbose);
    opts.addOption(bool, "shadow", shadow);

    // src/compat.zig calls libc directly (getaddrinfo, gettimeofday,
    // arc4random_buf/getrandom, …) for the std-library replacements that were
    // removed in zig 0.16.  macOS links libc by default, but on Linux zig
    // builds without libc unless we ask, so every module that pulls in compat
    // (or transitively pulls it via the zquic / tls modules) sets this.

    // tls module (vendored)
    const tls_mod = b.createModule(.{
        .root_source_file = b.path("vendor/tls/src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = needs_libc,
    });

    // Main library module (exposed as `zquic` for `build.zig.zon` dependents).
    const zig_varint_mod = b.dependency("zig_varint", .{
        .target = target,
        .optimize = optimize,
    }).module("zig_varint");

    const zquic_mod = b.addModule("zquic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = needs_libc,
    });
    zquic_mod.addImport("tls", tls_mod);
    zquic_mod.addImport("zig_varint", zig_varint_mod);
    zquic_mod.addOptions("build_options", opts);

    const lib = b.addLibrary(.{
        .name = "zquic",
        .root_module = zquic_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // Server binary
    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/cmd/server.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = needs_libc,
    });
    server_mod.addImport("zquic", zquic_mod);
    server_mod.addImport("tls", tls_mod);
    server_mod.addOptions("build_options", opts);
    const server = b.addExecutable(.{
        .name = "server",
        .root_module = server_mod,
    });
    b.installArtifact(server);

    // Client binary
    const client_mod = b.createModule(.{
        .root_source_file = b.path("src/cmd/client.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = needs_libc,
    });
    client_mod.addImport("zquic", zquic_mod);
    client_mod.addImport("tls", tls_mod);
    client_mod.addOptions("build_options", opts);
    const client = b.addExecutable(.{
        .name = "client",
        .root_module = client_mod,
    });
    b.installArtifact(client);

    // Unit tests
    const test_filters = b.option([]const []const u8, "test-filter", "Only run tests whose name matches a filter") orelse &.{};
    const unit_tests = b.addTest(.{
        .root_module = zquic_mod,
        .filters = test_filters,
    });
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // ── Benchmarks ───────────────────────────────────────────────────────────
    // zig build bench        — crypto path microbenchmark (runs immediately)
    // zig build bench-e2e    — end-to-end loopback transfer (needs server+client)
    // zig build bench-qpack  — QPACK static table lookup benchmark
    {
        const bench_step = b.step("bench", "Run crypto path microbenchmark");
        const m = b.createModule(.{
            .root_source_file = b.path("benchmarks/crypto_bench.zig"),
            .target = target,
            .optimize = if (optimize == .Debug) .ReleaseFast else optimize,
            .link_libc = needs_libc,
        });
        const exe = b.addExecutable(.{ .name = "crypto_bench", .root_module = m });
        const run = b.addRunArtifact(exe);
        if (b.args) |a| run.addArgs(a);
        bench_step.dependOn(&run.step);
    }
    {
        const bench_e2e_step = b.step("bench-e2e", "Run end-to-end loopback throughput benchmark");
        const m = b.createModule(.{
            .root_source_file = b.path("benchmarks/throughput_bench.zig"),
            .target = target,
            .optimize = if (optimize == .Debug) .ReleaseFast else optimize,
            .link_libc = needs_libc,
        });
        // Compat shim (Address, fs, milliTimestamp, …) for std calls
        // removed in 0.16.  Imported as `compat` from the bench source.
        const compat_mod = b.createModule(.{
            .root_source_file = b.path("src/compat.zig"),
            .target = target,
            .optimize = if (optimize == .Debug) .ReleaseFast else optimize,
            .link_libc = needs_libc,
        });
        m.addImport("compat", compat_mod);
        const exe = b.addExecutable(.{ .name = "throughput_bench", .root_module = m });
        const run = b.addRunArtifact(exe);
        if (b.args) |a| run.addArgs(a);
        // Ensure the server and client binaries are installed before the
        // benchmark executable runs.  The dependency must be on run.step (not
        // just the bench_e2e_step) so that the build system serialises install
        // → run rather than allowing them to execute in parallel.
        run.step.dependOn(b.getInstallStep());
        bench_e2e_step.dependOn(&run.step);
    }
    {
        const bench_qpack_step = b.step("bench-qpack", "Run QPACK static table lookup benchmark");
        const m = b.createModule(.{
            .root_source_file = b.path("benchmarks/qpack_bench.zig"),
            .target = target,
            .optimize = if (optimize == .Debug) .ReleaseFast else optimize,
            .link_libc = needs_libc,
        });
        m.addImport("zquic", zquic_mod);
        const exe = b.addExecutable(.{ .name = "qpack_bench", .root_module = m });
        const run = b.addRunArtifact(exe);
        if (b.args) |a| run.addArgs(a);
        bench_qpack_step.dependOn(&run.step);
    }

    // Examples
    const examples_step = b.step("examples", "Build all examples");
    const example_files = [_][]const u8{
        "examples/echo_server.zig",
        "examples/parse_packet.zig",
        "examples/session_resumption.zig",
    };
    for (example_files) |src| {
        const base = std.fs.path.stem(src);
        const ex_mod = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
        });
        ex_mod.addImport("zquic", zquic_mod);
        const ex = b.addExecutable(.{
            .name = base,
            .root_module = ex_mod,
        });
        const ex_install = b.addInstallArtifact(ex, .{});
        examples_step.dependOn(&ex_install.step);
    }
}
