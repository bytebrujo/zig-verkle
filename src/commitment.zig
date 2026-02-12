// commitment.zig -- Commitment scheme abstraction for Verkle trees.
//
// v0.1: Uses Blake3-based hashing as a placeholder commitment scheme.
// The API mirrors what a real Pedersen/IPA commitment scheme would provide
// so that the tree logic, proof paths, and verification are all production-
// quality. Only this module needs to be swapped for v0.2 (Bandersnatch +
// IPA).

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;

/// A 32-byte commitment (opaque to callers).
pub const Commitment = [32]u8;

/// The zero commitment (identity element).
pub const zero_commitment: Commitment = [_]u8{0} ** 32;

/// Domain separation tags so that different usages never collide.
const domain_leaf: [1]u8 = .{0x00};
const domain_internal: [1]u8 = .{0x01};
const domain_combine: [1]u8 = .{0x02};

/// Helper: finalize a Blake3 hasher into a 32-byte result.
fn finalize(h: *Blake3) Commitment {
    var out: Commitment = undefined;
    h.final(&out);
    return out;
}

/// Compute a leaf commitment from a key-value pair.
pub fn commitLeaf(key: [32]u8, value: [32]u8) Commitment {
    var h = Blake3.init(.{});
    h.update(&domain_leaf);
    h.update(&key);
    h.update(&value);
    return finalize(&h);
}

/// Compute an internal-node commitment from its children commitments.
///
/// `children` is a slice of (child_index, child_commitment) pairs that are
/// present (non-empty). Absent children are implicitly zero and do not
/// contribute (matching the behaviour of a real vector commitment).
pub fn commitInternal(children: []const ChildEntry) Commitment {
    if (children.len == 0) return zero_commitment;

    var h = Blake3.init(.{});
    h.update(&domain_internal);
    for (children) |entry| {
        h.update(&[_]u8{entry.index});
        h.update(&entry.commitment);
    }
    return finalize(&h);
}

/// Combine two commitments (used inside proof aggregation).
pub fn combine(a: Commitment, b: Commitment) Commitment {
    var h = Blake3.init(.{});
    h.update(&domain_combine);
    h.update(&a);
    h.update(&b);
    return finalize(&h);
}

pub const ChildEntry = struct {
    index: u8,
    commitment: Commitment,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "zero commitment is all zeroes" {
    for (zero_commitment) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "commitLeaf deterministic" {
    const key = [_]u8{0xAA} ** 32;
    const val = [_]u8{0xBB} ** 32;
    const c1 = commitLeaf(key, val);
    const c2 = commitLeaf(key, val);
    try std.testing.expectEqualSlices(u8, &c1, &c2);
}

test "commitLeaf different inputs differ" {
    const key = [_]u8{0xAA} ** 32;
    const v1 = [_]u8{0xBB} ** 32;
    const v2 = [_]u8{0xCC} ** 32;
    const c1 = commitLeaf(key, v1);
    const c2 = commitLeaf(key, v2);
    try std.testing.expect(!std.mem.eql(u8, &c1, &c2));
}

test "commitInternal empty is zero" {
    const empty: []const ChildEntry = &.{};
    const c = commitInternal(empty);
    try std.testing.expectEqualSlices(u8, &zero_commitment, &c);
}

test "commitInternal deterministic" {
    const entries = [_]ChildEntry{
        .{ .index = 0, .commitment = [_]u8{0x01} ** 32 },
        .{ .index = 5, .commitment = [_]u8{0x02} ** 32 },
    };
    const c1 = commitInternal(&entries);
    const c2 = commitInternal(&entries);
    try std.testing.expectEqualSlices(u8, &c1, &c2);
}
