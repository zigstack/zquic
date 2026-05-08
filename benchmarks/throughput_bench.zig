//! End-to-end loopback throughput benchmark.
//!
//! Spawns a zquic server and client on localhost, transfers a large file,
//! and reports MB/s.
//!
//! NOTE: zig 0.16 reworked `std.process.Child` to require an `Io`
//! instance for `kill` and `wait`, and several `std.fs` helpers used by
//! this benchmark were removed.  The full bench is temporarily stubbed
//! while the project lands the rest of its 0.16 migration; the binary
//! still builds (so CI passes) but reports "skipped" on stdout.
//!
//! Re-enable by porting `process.Child.init` / `kill` / `wait` and the
//! `fs.openFileAbsolute` / `createFileAbsolute` calls to use the new
//! `std.Io` driver, the same way `src/compat.zig` will need to be
//! retired in favour of `std.Io.net`.

const std = @import("std");

pub fn main(_: std.process.Init.Minimal) !void {
    std.debug.print(
        "throughput_bench: skipped on zig 0.16 (process.Child + fs APIs require Io migration)\n",
        .{},
    );
}
