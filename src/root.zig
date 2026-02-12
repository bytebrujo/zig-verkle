// root.zig -- Public re-exports for the zig-verkle library.
//
// Import this module (or depend on the "zig-verkle" build module) to
// access the VerkleTree API.

pub const commitment = @import("commitment.zig");
pub const node = @import("node.zig");
pub const proof = @import("proof.zig");
pub const verkle_tree = @import("verkle_tree.zig");

pub const VerkleTree = verkle_tree.VerkleTree;
pub const Proof = proof.Proof;
pub const BatchProof = proof.BatchProof;
pub const Commitment = commitment.Commitment;

test {
    // Pull in tests from all sub-modules.
    @import("std").testing.refAllDecls(@This());
}
