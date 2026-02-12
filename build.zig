const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Public module that dependents can import as "zig-verkle"
    const verkle_mod = b.addModule("zig-verkle", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Static library artifact
    const lib = b.addLibrary(.{
        .name = "zig-verkle",
        .root_module = verkle_mod,
    });
    b.installArtifact(lib);

    // Unit tests -- run all tests via root.zig which re-exports sub-modules
    const test_step = b.step("test", "Run unit tests");

    const root_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(root_tests).step);
}
