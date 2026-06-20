//! ACK frame (RFC 9000 §19.3).
//!
//! Wire format:
//!   Type (varint)         0x02 or 0x03
//!   Largest Acknowledged (varint)
//!   ACK Delay (varint)
//!   ACK Range Count (varint)
//!   First ACK Range (varint)
//!   ACK Range[0..n] pairs:
//!     Gap (varint)
//!     ACK Range Length (varint)
//!   [ECN Counts if type=0x03]
//!     ECT0 Count (varint)
//!     ECT1 Count (varint)
//!     ECN-CE Count (varint)

const std = @import("std");
const varint = @import("../varint.zig");

pub const max_ack_ranges = 64;

pub const AckRange = struct {
    /// Smallest packet number acknowledged in this range.
    smallest: u64,
    /// Largest packet number acknowledged in this range.
    largest: u64,
};

pub const EcnCounts = struct {
    ect0: u64,
    ect1: u64,
    ecn_ce: u64,
};

pub const AckFrame = struct {
    largest_acknowledged: u64,
    /// ACK delay in microseconds (scaled by 2^ack_delay_exponent).
    ack_delay: u64,
    /// Decoded ranges (largest first).
    ranges: [max_ack_ranges]AckRange,
    range_count: usize,
    ecn: ?EcnCounts,

    /// Parse an ACK frame from `buf` (after the type byte).
    ///
    /// Returns `error.NonMinimalEncoding` for varints that violate RFC 9000 §16,
    /// and `error.FrameEncodingError` for ranges that underflow the packet
    /// number space (RFC 9000 §19.3: first_range must not exceed largest,
    /// additional gaps/lengths must not underflow).
    pub fn parse(buf: []const u8, has_ecn: bool) (varint.DecodeError || error{FrameEncodingError})!struct { frame: AckFrame, consumed: usize } {
        var r = varint.Reader.init(buf);

        const largest = try r.readVarint();
        const delay = try r.readVarint();
        const range_count = try r.readVarint();
        const first_range = try r.readVarint();

        // RFC 9000 §19.3: first_range must not exceed largest_acknowledged.
        if (first_range > largest) return error.FrameEncodingError;

        var frame: AckFrame = .{
            .largest_acknowledged = largest,
            .ack_delay = delay,
            .ranges = undefined,
            .range_count = 0,
            .ecn = null,
        };

        // First range: [largest - first_range, largest]
        frame.ranges[0] = .{
            .largest = largest,
            .smallest = largest - first_range,
        };
        frame.range_count = 1;

        // Additional ranges
        var i: usize = 0;
        var current_smallest = frame.ranges[0].smallest;
        while (i < range_count and frame.range_count < max_ack_ranges) : (i += 1) {
            const gap = try r.readVarint();
            const range_len = try r.readVarint();
            // RFC 9000 §19.3.1: additional ranges must not underflow the PN space.
            // gap + 2 must be <= current_smallest, and range_len must be <= the
            // computed range_largest.  We use checked arithmetic to reject
            // malformed ACKs instead of silently clamping.
            if (gap >= current_smallest) return error.FrameEncodingError;
            // gap + 2 could overflow u64 if gap is near max, but earlier check
            // (gap < current_smallest ≤ 2^62) means gap+2 is safe.
            if (gap + 2 > current_smallest) return error.FrameEncodingError;
            const range_largest = current_smallest - (gap + 2);
            if (range_len > range_largest) return error.FrameEncodingError;
            const range_smallest = range_largest - range_len;
            frame.ranges[frame.range_count] = .{
                .largest = range_largest,
                .smallest = range_smallest,
            };
            frame.range_count += 1;
            current_smallest = range_smallest;
        }

        if (has_ecn) {
            const ect0 = try r.readVarint();
            const ect1 = try r.readVarint();
            const ecn_ce = try r.readVarint();
            frame.ecn = .{ .ect0 = ect0, .ect1 = ect1, .ecn_ce = ecn_ce };
        }

        return .{ .frame = frame, .consumed = r.pos };
    }

    /// Serialize the ACK frame into `buf`. Returns bytes written.
    pub fn serialize(self: AckFrame, buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
        var w = varint.Writer.init(buf);
        // Type
        try w.writeVarint(if (self.ecn != null) 0x03 else 0x02);
        try w.writeVarint(self.largest_acknowledged);
        try w.writeVarint(self.ack_delay);

        // Number of additional ranges (total - 1)
        const additional = if (self.range_count > 0) self.range_count - 1 else 0;
        try w.writeVarint(additional);

        // First range
        if (self.range_count > 0) {
            const first = self.ranges[0];
            try w.writeVarint(first.largest - first.smallest);

            // Additional ranges
            var i: usize = 1;
            var prev_smallest = first.smallest;
            while (i < self.range_count) : (i += 1) {
                const r = self.ranges[i];
                // gap = prev_smallest - r.largest - 2. Defensive: ranges are
                // expected to be non-overlapping and ≥2 apart (callers coalesce
                // first), but a malformed/adjacent pair must never panic the
                // node on an integer overflow — saturate to 0 instead.
                const gap = if (prev_smallest -| r.largest >= 2) prev_smallest - r.largest - 2 else 0;
                try w.writeVarint(gap);
                try w.writeVarint(r.largest -| r.smallest);
                prev_smallest = r.smallest;
            }
        }

        if (self.ecn) |ecn| {
            try w.writeVarint(ecn.ect0);
            try w.writeVarint(ecn.ect1);
            try w.writeVarint(ecn.ecn_ce);
        }

        return w.pos;
    }

    /// Returns true if `pn` is acknowledged by this ACK frame.
    pub fn acknowledges(self: AckFrame, pn: u64) bool {
        for (self.ranges[0..self.range_count]) |r| {
            if (pn >= r.smallest and pn <= r.largest) return true;
        }
        return false;
    }
};

test "ack: single range parse/serialize round-trip" {
    const testing = std.testing;

    // Serialize an ACK: largest=10, delay=0, first_range=5 → acks [5..10]
    var buf: [64]u8 = undefined;
    var w = varint.Writer.init(&buf);
    try w.writeVarint(0x02); // type
    try w.writeVarint(10); // largest
    try w.writeVarint(0); // delay
    try w.writeVarint(0); // range count (0 additional)
    try w.writeVarint(5); // first range

    const r = try AckFrame.parse(buf[1..w.pos], false);
    try testing.expectEqual(@as(u64, 10), r.frame.largest_acknowledged);
    try testing.expectEqual(@as(usize, 1), r.frame.range_count);
    try testing.expectEqual(@as(u64, 5), r.frame.ranges[0].smallest);
    try testing.expectEqual(@as(u64, 10), r.frame.ranges[0].largest);
    try testing.expect(r.frame.acknowledges(7));
    try testing.expect(!r.frame.acknowledges(4));
    try testing.expect(!r.frame.acknowledges(11));
}

test "ack: serialize and re-parse" {
    const testing = std.testing;

    var frame = AckFrame{
        .largest_acknowledged = 100,
        .ack_delay = 500,
        .ranges = undefined,
        .range_count = 2,
        .ecn = null,
    };
    frame.ranges[0] = .{ .largest = 100, .smallest = 90 };
    frame.ranges[1] = .{ .largest = 80, .smallest = 70 };

    var buf: [64]u8 = undefined;
    const written = try frame.serialize(&buf);
    try testing.expect(written > 0);

    // Skip the type byte that serialize() writes
    const r = try AckFrame.parse(buf[1..written], false);
    try testing.expectEqual(@as(u64, 100), r.frame.largest_acknowledged);
    try testing.expectEqual(@as(u64, 500), r.frame.ack_delay);
    try testing.expectEqual(@as(usize, 2), r.frame.range_count);
    try testing.expect(r.frame.acknowledges(95));
    try testing.expect(r.frame.acknowledges(75));
    try testing.expect(!r.frame.acknowledges(85));
}
