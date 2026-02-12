// proof.zig -- Proof generation and verification for the Verkle trie.
//
// A proof for a key consists of:
//   - The commitments along the path from the root to the leaf (or the
//     point at which the key is absent).
//   - At each level, the sibling commitments needed to recompute the
//     parent commitment (the full child-entry set for that internal node,
//     minus the child on the path, which the verifier can recompute).
//
// For v0.1 (Blake3 placeholder), the verifier re-derives commitments
// bottom-up and checks that the reconstructed root matches. When the
// commitment scheme is upgraded to Pedersen/IPA, the proof structure
// and verification logic adapt accordingly.

const std = @import("std");
const Allocator = std.mem.Allocator;
const commitment = @import("commitment.zig");
const Commitment = commitment.Commitment;
const node_mod = @import("node.zig");
const InternalNode = node_mod.InternalNode;
const Node = node_mod.Node;

/// A single level of a Verkle proof.
pub const ProofLevel = struct {
    /// Index of the child on the path at this depth.
    child_index: u8,
    /// Sibling (child_index, commitment) pairs for all *other* non-null
    /// children of the internal node at this depth.
    siblings: []const commitment.ChildEntry,
};

/// Proof for a single key.
pub const Proof = struct {
    /// Path levels from root (index 0) to the deepest internal node on
    /// the path.
    levels: []const ProofLevel,
    /// The commitment of the leaf (or zero_commitment if absent).
    leaf_commitment: Commitment,
    /// Depth at which the leaf (or absence) was found.
    depth: u8,

    pub fn deinit(self: *const Proof, allocator: Allocator) void {
        for (self.levels) |level| {
            allocator.free(level.siblings);
        }
        allocator.free(self.levels);
    }
};

/// Aggregated proof for multiple keys. For v0.1 this is simply a
/// collection of individual proofs (a real IPA multi-proof would be
/// much smaller).
pub const BatchProof = struct {
    proofs: []const Proof,

    pub fn deinit(self: *const BatchProof, allocator: Allocator) void {
        for (self.proofs) |p| {
            p.deinit(allocator);
        }
        allocator.free(self.proofs);
    }
};

// ---------------------------------------------------------------------------
// Proof generation
// ---------------------------------------------------------------------------

/// Generate a proof for `key` starting at `root_node`.
pub fn generateProof(
    allocator: Allocator,
    root_node: *InternalNode,
    key: [32]u8,
) !Proof {
    var levels: std.ArrayList(ProofLevel) = .empty;
    errdefer {
        for (levels.items) |level| allocator.free(level.siblings);
        levels.deinit(allocator);
    }

    var current: *InternalNode = root_node;
    var depth: u8 = 0;

    while (depth < node_mod.max_depth) {
        const child_idx = key[depth];

        // Collect sibling entries.
        var sibling_list: std.ArrayList(commitment.ChildEntry) = .empty;
        errdefer sibling_list.deinit(allocator);

        for (current.children, 0..) |child_opt, idx| {
            if (idx == child_idx) continue;
            if (child_opt) |child| {
                const c = switch (child) {
                    .leaf => |leaf| commitment.commitLeaf(leaf.key, leaf.value),
                    .internal => |internal| try internal.computeCommitment(allocator),
                };
                try sibling_list.append(allocator, .{
                    .index = @intCast(idx),
                    .commitment = c,
                });
            }
        }

        try levels.append(allocator, .{
            .child_index = child_idx,
            .siblings = try sibling_list.toOwnedSlice(allocator),
        });

        const child_opt = current.children[child_idx];
        if (child_opt) |child| {
            switch (child) {
                .leaf => |leaf| {
                    // Reached a leaf -- the proof ends here.
                    const leaf_c = commitment.commitLeaf(leaf.key, leaf.value);
                    return Proof{
                        .levels = try levels.toOwnedSlice(allocator),
                        .leaf_commitment = leaf_c,
                        .depth = depth + 1,
                    };
                },
                .internal => |internal| {
                    current = internal;
                    depth += 1;
                },
            }
        } else {
            // Key is absent.
            return Proof{
                .levels = try levels.toOwnedSlice(allocator),
                .leaf_commitment = commitment.zero_commitment,
                .depth = depth + 1,
            };
        }
    }

    // Should not happen for well-formed trees with 32-byte keys, but
    // handle gracefully.
    return Proof{
        .levels = try levels.toOwnedSlice(allocator),
        .leaf_commitment = commitment.zero_commitment,
        .depth = depth,
    };
}

// ---------------------------------------------------------------------------
// Proof verification
// ---------------------------------------------------------------------------

/// Verify a proof for `key` with expected `value` (null means absence)
/// against a known `root` commitment.
pub fn verifyProof(
    root: Commitment,
    key: [32]u8,
    value: ?[32]u8,
    proof: Proof,
) bool {
    // 1. Determine the leaf commitment the verifier expects.
    const expected_leaf: Commitment = if (value) |v|
        commitment.commitLeaf(key, v)
    else
        commitment.zero_commitment;

    // The proof's leaf_commitment must match.
    if (!std.mem.eql(u8, &expected_leaf, &proof.leaf_commitment)) return false;

    // 2. Walk from the bottom of the proof up to the root, recomputing
    //    each internal-node commitment.
    var current_commitment = expected_leaf;
    const is_zero = std.mem.eql(u8, &current_commitment, &commitment.zero_commitment);

    // Iterate levels in reverse (deepest first).
    var i: usize = proof.levels.len;
    while (i > 0) {
        i -= 1;
        const level = proof.levels[i];

        // If current_commitment is zero_commitment, the child at this
        // level is absent. Absent children are not included in
        // commitInternal, so we only use the siblings.
        const include_path_child = !(is_zero and i == proof.levels.len - 1);

        const entry_count = level.siblings.len + @as(usize, if (include_path_child) 1 else 0);

        // Use a stack buffer -- bounded by 256 so a stack array is fine.
        var buf: [256]commitment.ChildEntry = undefined;
        var pos: usize = 0;
        var sib_pos: usize = 0;
        var inserted_path = !include_path_child; // skip if absent

        while (pos < entry_count) {
            const sib_available = sib_pos < level.siblings.len;
            const sib_index: u16 = if (sib_available) level.siblings[sib_pos].index else 256;

            if (!inserted_path and @as(u16, level.child_index) <= sib_index) {
                buf[pos] = .{
                    .index = level.child_index,
                    .commitment = current_commitment,
                };
                inserted_path = true;
            } else if (sib_available) {
                buf[pos] = level.siblings[sib_pos];
                sib_pos += 1;
            }
            pos += 1;
        }

        current_commitment = commitment.commitInternal(buf[0..entry_count]);
    }

    return std.mem.eql(u8, &current_commitment, &root);
}

/// Generate proofs for multiple keys (batch).
pub fn generateBatchProof(
    allocator: Allocator,
    root_node: *InternalNode,
    keys: []const [32]u8,
) !BatchProof {
    const proofs = try allocator.alloc(Proof, keys.len);
    errdefer {
        // Free any proofs that were successfully generated.
        for (proofs) |p| p.deinit(allocator);
        allocator.free(proofs);
    }

    // Initialize all proofs to a known state so errdefer cleanup is safe.
    for (proofs) |*p| {
        p.* = Proof{
            .levels = &.{},
            .leaf_commitment = commitment.zero_commitment,
            .depth = 0,
        };
    }

    for (keys, 0..) |key, i| {
        proofs[i] = try generateProof(allocator, root_node, key);
    }

    return BatchProof{ .proofs = proofs };
}

/// Verify a batch proof.
pub fn verifyBatchProof(
    root: Commitment,
    keys: []const [32]u8,
    values: []const ?[32]u8,
    batch_proof: BatchProof,
) bool {
    if (keys.len != values.len) return false;
    if (keys.len != batch_proof.proofs.len) return false;

    for (keys, 0..) |key, i| {
        if (!verifyProof(root, key, values[i], batch_proof.proofs[i])) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "proof round-trip single leaf" {
    const allocator = std.testing.allocator;

    var root_node = try InternalNode.create(allocator);
    defer root_node.destroy(allocator);

    const key = [_]u8{0x42} ** 32;
    const val = [_]u8{0xFF} ** 32;
    root_node.children[0x42] = Node{ .leaf = .{ .key = key, .value = val } };

    const root_c = try root_node.computeCommitment(allocator);

    const proof = try generateProof(allocator, root_node, key);
    defer proof.deinit(allocator);

    try std.testing.expect(verifyProof(root_c, key, val, proof));
}

test "proof fails with wrong value" {
    const allocator = std.testing.allocator;

    var root_node = try InternalNode.create(allocator);
    defer root_node.destroy(allocator);

    const key = [_]u8{0x42} ** 32;
    const val = [_]u8{0xFF} ** 32;
    root_node.children[0x42] = Node{ .leaf = .{ .key = key, .value = val } };

    const root_c = try root_node.computeCommitment(allocator);

    const proof = try generateProof(allocator, root_node, key);
    defer proof.deinit(allocator);

    const wrong_val = [_]u8{0xEE} ** 32;
    try std.testing.expect(!verifyProof(root_c, key, wrong_val, proof));
}

test "proof for absent key" {
    const allocator = std.testing.allocator;

    var root_node = try InternalNode.create(allocator);
    defer root_node.destroy(allocator);

    const key_present = [_]u8{0x42} ** 32;
    const val = [_]u8{0xFF} ** 32;
    root_node.children[0x42] = Node{ .leaf = .{ .key = key_present, .value = val } };

    const root_c = try root_node.computeCommitment(allocator);

    const key_absent = [_]u8{0x43} ** 32;
    const proof = try generateProof(allocator, root_node, key_absent);
    defer proof.deinit(allocator);

    // Absent key should verify with null value.
    try std.testing.expect(verifyProof(root_c, key_absent, null, proof));
    // And should NOT verify with a non-null value.
    try std.testing.expect(!verifyProof(root_c, key_absent, val, proof));
}
