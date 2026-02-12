// verkle_tree.zig -- Main VerkleTree implementation.
//
// A 256-ary trie where each byte of a 32-byte key selects a child at
// that depth. Leaves store key-value pairs. Internal nodes aggregate
// child commitments via the commitment scheme (Blake3 placeholder for
// v0.1, Pedersen/IPA in v0.2).

const std = @import("std");
const Allocator = std.mem.Allocator;

const commitment = @import("commitment.zig");
const Commitment = commitment.Commitment;
const node_mod = @import("node.zig");
const InternalNode = node_mod.InternalNode;
const Node = node_mod.Node;
const LeafNode = node_mod.LeafNode;
const proof_mod = @import("proof.zig");

pub const Proof = proof_mod.Proof;
pub const BatchProof = proof_mod.BatchProof;

pub const VerkleTree = struct {
    allocator: Allocator,
    root: *InternalNode,

    /// Create a new, empty Verkle tree.
    pub fn init(allocator: Allocator) !VerkleTree {
        return VerkleTree{
            .allocator = allocator,
            .root = try InternalNode.create(allocator),
        };
    }

    /// Release all memory owned by the tree.
    pub fn deinit(self: *VerkleTree) void {
        self.root.destroy(self.allocator);
    }

    // -----------------------------------------------------------------------
    // Mutations
    // -----------------------------------------------------------------------

    /// Insert or update a key-value pair.
    pub fn insert(self: *VerkleTree, key: [32]u8, value: [32]u8) !void {
        try self.insertAt(self.root, key, value, 0);
    }

    /// Delete a key. Returns `error.KeyNotFound` if the key does not exist.
    pub fn delete(self: *VerkleTree, key: [32]u8) !void {
        try self.deleteAt(self.root, key, 0);
    }

    /// Insert a batch of key-value pairs.
    pub fn insertBatch(self: *VerkleTree, keys: []const [32]u8, values: []const [32]u8) !void {
        std.debug.assert(keys.len == values.len);
        for (keys, 0..) |key, i| {
            try self.insert(key, values[i]);
        }
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Look up a value by key. Returns null if the key is not present.
    pub fn get(self: *VerkleTree, key: [32]u8) ?[32]u8 {
        return self.getAt(self.root, key, 0);
    }

    // -----------------------------------------------------------------------
    // Commitments
    // -----------------------------------------------------------------------

    /// Compute and return the 32-byte root commitment (state root).
    pub fn commit(self: *VerkleTree) ![32]u8 {
        return try self.root.computeCommitment(self.allocator);
    }

    // -----------------------------------------------------------------------
    // Proofs
    // -----------------------------------------------------------------------

    /// Generate a proof of inclusion (or absence) for a single key.
    pub fn prove(self: *VerkleTree, key: [32]u8) !Proof {
        // Ensure commitments are computed before generating the proof.
        _ = try self.root.computeCommitment(self.allocator);
        return try proof_mod.generateProof(self.allocator, self.root, key);
    }

    /// Verify a proof against a root commitment.
    pub fn verify(root_commitment: [32]u8, key: [32]u8, value: ?[32]u8, proof: Proof) !bool {
        return proof_mod.verifyProof(root_commitment, key, value, proof);
    }

    /// Generate a batch proof for multiple keys.
    pub fn proveBatch(self: *VerkleTree, keys: []const [32]u8) !BatchProof {
        _ = try self.root.computeCommitment(self.allocator);
        return try proof_mod.generateBatchProof(self.allocator, self.root, keys);
    }

    /// Verify a batch proof.
    pub fn verifyBatch(root_commitment: [32]u8, keys: []const [32]u8, values: []const ?[32]u8, proof: BatchProof) !bool {
        return proof_mod.verifyBatchProof(root_commitment, keys, values, proof);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn insertAt(self: *VerkleTree, current: *InternalNode, key: [32]u8, value: [32]u8, depth: u8) !void {
        if (depth >= node_mod.max_depth) return; // should not happen

        const child_idx = key[depth];
        current.invalidate();

        const child_opt = current.children[child_idx];

        if (child_opt == null) {
            // Empty slot -- place a leaf here.
            current.children[child_idx] = Node{
                .leaf = LeafNode{ .key = key, .value = value },
            };
            return;
        }

        switch (child_opt.?) {
            .leaf => |existing_leaf| {
                if (std.mem.eql(u8, &existing_leaf.key, &key)) {
                    // Same key -- update value.
                    current.children[child_idx] = Node{
                        .leaf = LeafNode{ .key = key, .value = value },
                    };
                    return;
                }

                // Collision -- we need to push both leaves deeper.
                // Create a new internal node and re-insert both.
                const new_internal = try InternalNode.create(self.allocator);
                errdefer new_internal.destroy(self.allocator);
                current.children[child_idx] = Node{ .internal = new_internal };

                try self.insertAt(new_internal, existing_leaf.key, existing_leaf.value, depth + 1);
                try self.insertAt(new_internal, key, value, depth + 1);
            },
            .internal => |internal| {
                try self.insertAt(internal, key, value, depth + 1);
            },
        }
    }

    fn getAt(self: *VerkleTree, current: *InternalNode, key: [32]u8, depth: u8) ?[32]u8 {
        if (depth >= node_mod.max_depth) return null;

        const child_idx = key[depth];
        const child_opt = current.children[child_idx];

        if (child_opt == null) return null;

        return switch (child_opt.?) {
            .leaf => |leaf| if (std.mem.eql(u8, &leaf.key, &key)) leaf.value else null,
            .internal => |internal| self.getAt(internal, key, depth + 1),
        };
    }

    fn deleteAt(self: *VerkleTree, current: *InternalNode, key: [32]u8, depth: u8) !void {
        if (depth >= node_mod.max_depth) return error.KeyNotFound;

        const child_idx = key[depth];
        current.invalidate();

        const child_opt = current.children[child_idx];

        if (child_opt == null) return error.KeyNotFound;

        switch (child_opt.?) {
            .leaf => |leaf| {
                if (!std.mem.eql(u8, &leaf.key, &key)) return error.KeyNotFound;
                current.children[child_idx] = null;
            },
            .internal => |internal| {
                try self.deleteAt(internal, key, depth + 1);

                // If the internal node now has exactly one child that is
                // a leaf, collapse it upward (trie compression).
                const count = internal.childCount();
                if (count == 0) {
                    internal.destroy(self.allocator);
                    current.children[child_idx] = null;
                } else if (count == 1) {
                    // Find the single remaining child.
                    for (internal.children) |c_opt| {
                        if (c_opt) |c| {
                            switch (c) {
                                .leaf => |remaining_leaf| {
                                    current.children[child_idx] = Node{ .leaf = remaining_leaf };
                                    // We only destroy the internal node shell, its
                                    // child is now referenced by the parent.
                                    // Clear children first to avoid double-free.
                                    internal.children = [_]?Node{null} ** 256;
                                    internal.destroy(self.allocator);
                                },
                                .internal => {
                                    // Single child is internal -- don't collapse.
                                    break;
                                },
                            }
                            break;
                        }
                    }
                }
            },
        }
    }

    pub const Error = error{KeyNotFound} || Allocator.Error;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "basic insert and get" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = [_]u8{0x01} ** 32;
    const val = [_]u8{0xAB} ** 32;

    try tree.insert(key, val);
    const got = tree.get(key);
    try std.testing.expect(got != null);
    try std.testing.expectEqualSlices(u8, &val, &got.?);
}

test "get missing key returns null" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = [_]u8{0x01} ** 32;
    try std.testing.expect(tree.get(key) == null);
}

test "insert, commit, get -- root changes" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const root_empty = try tree.commit();

    const key = [_]u8{0x01} ** 32;
    const val = [_]u8{0xAB} ** 32;
    try tree.insert(key, val);

    const root_after = try tree.commit();

    // Root must change after insertion.
    try std.testing.expect(!std.mem.eql(u8, &root_empty, &root_after));
    // Value must be retrievable.
    try std.testing.expectEqualSlices(u8, &val, &tree.get(key).?);
}

test "delete key" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = [_]u8{0x01} ** 32;
    const val = [_]u8{0xAB} ** 32;
    try tree.insert(key, val);
    try std.testing.expect(tree.get(key) != null);

    try tree.delete(key);
    try std.testing.expect(tree.get(key) == null);
}

test "delete missing key returns error" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = [_]u8{0x01} ** 32;
    try std.testing.expectError(error.KeyNotFound, tree.delete(key));
}

test "proof generation and verification (single key)" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = [_]u8{0x01} ** 32;
    const val = [_]u8{0xAB} ** 32;
    try tree.insert(key, val);

    const root_c = try tree.commit();

    const proof = try tree.prove(key);
    defer proof.deinit(std.testing.allocator);

    const valid = try VerkleTree.verify(root_c, key, val, proof);
    try std.testing.expect(valid);
}

test "proof verification fails with wrong value" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = [_]u8{0x01} ** 32;
    const val = [_]u8{0xAB} ** 32;
    try tree.insert(key, val);

    const root_c = try tree.commit();

    const proof = try tree.prove(key);
    defer proof.deinit(std.testing.allocator);

    const wrong_val = [_]u8{0xCD} ** 32;
    const valid = try VerkleTree.verify(root_c, key, wrong_val, proof);
    try std.testing.expect(!valid);
}

test "batch insert" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    var keys: [10][32]u8 = undefined;
    var vals: [10][32]u8 = undefined;
    for (0..10) |i| {
        keys[i] = [_]u8{0} ** 32;
        keys[i][0] = @intCast(i);
        vals[i] = [_]u8{0} ** 32;
        vals[i][0] = @intCast(i + 100);
    }

    try tree.insertBatch(&keys, &vals);

    for (0..10) |i| {
        const got = tree.get(keys[i]);
        try std.testing.expect(got != null);
        try std.testing.expectEqualSlices(u8, &vals[i], &got.?);
    }
}

test "batch proof generation and verification" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    var keys: [5][32]u8 = undefined;
    var vals: [5][32]u8 = undefined;
    for (0..5) |i| {
        keys[i] = [_]u8{0} ** 32;
        keys[i][0] = @intCast(i);
        vals[i] = [_]u8{0} ** 32;
        vals[i][0] = @intCast(i + 50);
    }
    try tree.insertBatch(&keys, &vals);

    const root_c = try tree.commit();

    const batch_proof = try tree.proveBatch(&keys);
    defer batch_proof.deinit(std.testing.allocator);

    var opt_vals: [5]?[32]u8 = undefined;
    for (0..5) |i| {
        opt_vals[i] = vals[i];
    }

    const valid = try VerkleTree.verifyBatch(root_c, &keys, &opt_vals, batch_proof);
    try std.testing.expect(valid);
}

test "empty tree commit returns known root" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const root = try tree.commit();

    // An empty tree should produce the zero commitment.
    try std.testing.expectEqualSlices(u8, &commitment.zero_commitment, &root);
}

test "large tree (1000+ entries) insert and prove" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const count = 1024;
    var keys: [count][32]u8 = undefined;
    var vals: [count][32]u8 = undefined;

    for (0..count) |i| {
        // Distribute keys across the trie by using the index as the
        // first two bytes.
        keys[i] = [_]u8{0} ** 32;
        keys[i][0] = @intCast(i >> 8);
        keys[i][1] = @intCast(i & 0xFF);
        vals[i] = [_]u8{0} ** 32;
        vals[i][0] = @intCast(i >> 8);
        vals[i][1] = @intCast(i & 0xFF);
        vals[i][31] = 0x01; // distinguish from key

        try tree.insert(keys[i], vals[i]);
    }

    const root_c = try tree.commit();

    // Verify a sample of proofs (all 1024 would be slow in debug mode).
    const sample_indices = [_]usize{ 0, 1, 255, 256, 511, 512, 1023 };
    for (sample_indices) |idx| {
        const proof = try tree.prove(keys[idx]);
        defer proof.deinit(std.testing.allocator);

        const valid = try VerkleTree.verify(root_c, keys[idx], vals[idx], proof);
        try std.testing.expect(valid);
    }
}

test "re-insert (update existing key) changes root" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = [_]u8{0x01} ** 32;
    const val1 = [_]u8{0xAA} ** 32;
    const val2 = [_]u8{0xBB} ** 32;

    try tree.insert(key, val1);
    const root1 = try tree.commit();

    try tree.insert(key, val2);
    const root2 = try tree.commit();

    try std.testing.expect(!std.mem.eql(u8, &root1, &root2));

    // The new value should be retrievable.
    try std.testing.expectEqualSlices(u8, &val2, &tree.get(key).?);
}

test "collision handling: keys sharing a prefix" {
    var tree = try VerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    // Two keys that share the first byte but differ at byte 1.
    var key1 = [_]u8{0} ** 32;
    key1[0] = 0xAA;
    key1[1] = 0x01;

    var key2 = [_]u8{0} ** 32;
    key2[0] = 0xAA;
    key2[1] = 0x02;

    const val1 = [_]u8{0x11} ** 32;
    const val2 = [_]u8{0x22} ** 32;

    try tree.insert(key1, val1);
    try tree.insert(key2, val2);

    try std.testing.expectEqualSlices(u8, &val1, &tree.get(key1).?);
    try std.testing.expectEqualSlices(u8, &val2, &tree.get(key2).?);

    // Both should be provable.
    const root_c = try tree.commit();

    const proof1 = try tree.prove(key1);
    defer proof1.deinit(std.testing.allocator);
    try std.testing.expect(try VerkleTree.verify(root_c, key1, val1, proof1));

    const proof2 = try tree.prove(key2);
    defer proof2.deinit(std.testing.allocator);
    try std.testing.expect(try VerkleTree.verify(root_c, key2, val2, proof2));
}
