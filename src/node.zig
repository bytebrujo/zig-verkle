// node.zig -- Internal and leaf node types for the 256-ary Verkle trie.
//
// The trie is a radix-256 tree where each byte of a 32-byte key selects
// one of 256 children at each depth level (max depth = 32).

const std = @import("std");
const Allocator = std.mem.Allocator;
const commitment = @import("commitment.zig");
const Commitment = commitment.Commitment;

/// Maximum depth of the trie (one level per key byte).
pub const max_depth: u8 = 32;

/// Width of each internal node (children per node).
pub const width: u16 = 256;

pub const Node = union(enum) {
    leaf: LeafNode,
    internal: *InternalNode,
};

pub const LeafNode = struct {
    key: [32]u8,
    value: [32]u8,
};

pub const InternalNode = struct {
    children: [256]?Node = [_]?Node{null} ** 256,
    /// Cached commitment -- invalidated (set to null) on mutation.
    cached_commitment: ?Commitment = null,

    pub fn create(allocator: Allocator) !*InternalNode {
        const node = try allocator.create(InternalNode);
        node.* = .{};
        return node;
    }

    pub fn destroy(self: *InternalNode, allocator: Allocator) void {
        for (&self.children) |*child| {
            if (child.*) |c| {
                switch (c) {
                    .internal => |internal| internal.destroy(allocator),
                    .leaf => {},
                }
                child.* = null;
            }
        }
        allocator.destroy(self);
    }

    /// Invalidate the cached commitment for this node.
    pub fn invalidate(self: *InternalNode) void {
        self.cached_commitment = null;
    }

    /// Count non-null children.
    pub fn childCount(self: *const InternalNode) u16 {
        var count: u16 = 0;
        for (self.children) |child| {
            if (child != null) count += 1;
        }
        return count;
    }

    /// Compute (and cache) the commitment for this internal node.
    /// Recursively commits children as needed.
    pub fn computeCommitment(self: *InternalNode, allocator: Allocator) !Commitment {
        if (self.cached_commitment) |c| return c;

        // Gather non-null children commitments.
        var entries_buf: [256]commitment.ChildEntry = undefined;
        var entry_count: usize = 0;
        for (self.children, 0..) |child_opt, idx| {
            if (child_opt) |child| {
                const child_commit = switch (child) {
                    .leaf => |leaf| commitment.commitLeaf(leaf.key, leaf.value),
                    .internal => |internal| try internal.computeCommitment(allocator),
                };
                entries_buf[entry_count] = .{
                    .index = @intCast(idx),
                    .commitment = child_commit,
                };
                entry_count += 1;
            }
        }

        const c = commitment.commitInternal(entries_buf[0..entry_count]);
        self.cached_commitment = c;
        return c;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "InternalNode create and destroy" {
    const allocator = std.testing.allocator;
    const node = try InternalNode.create(allocator);
    defer node.destroy(allocator);

    try std.testing.expectEqual(@as(u16, 0), node.childCount());
}

test "InternalNode insert leaf child" {
    const allocator = std.testing.allocator;
    const node = try InternalNode.create(allocator);
    defer node.destroy(allocator);

    node.children[42] = Node{ .leaf = .{
        .key = [_]u8{0xAA} ** 32,
        .value = [_]u8{0xBB} ** 32,
    } };
    try std.testing.expectEqual(@as(u16, 1), node.childCount());
}

test "InternalNode commitment caching" {
    const allocator = std.testing.allocator;
    const node = try InternalNode.create(allocator);
    defer node.destroy(allocator);

    node.children[0] = Node{ .leaf = .{
        .key = [_]u8{0x00} ** 32,
        .value = [_]u8{0xFF} ** 32,
    } };

    const c1 = try node.computeCommitment(allocator);
    const c2 = try node.computeCommitment(allocator);
    try std.testing.expectEqualSlices(u8, &c1, &c2);

    // After invalidation, re-computation should yield the same result.
    node.invalidate();
    const c3 = try node.computeCommitment(allocator);
    try std.testing.expectEqualSlices(u8, &c1, &c3);
}
