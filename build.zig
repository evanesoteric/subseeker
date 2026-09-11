const std = @import("std");

// Build script for subseeker. Tested with Zig 0.16.0.
//
//   zig build                          -> builds ./zig-out/bin/subseeker (Debug)
//   zig build -Doptimize=ReleaseSafe    -> optimized, safety checks on (recommended for releases)
//   zig build -Doptimize=ReleaseFast    -> optimized, fewer checks
//   zig build -Dtarget=aarch64-linux    -> cross-compile
//   zig build run -- <args>             -> build then run; args after `--` go to subseeker
pub fn build(b: *std.Build) void {
    // Exposes -Dtarget=... (defaults to the host).
    const target = b.standardTargetOptions(.{});

    // Exposes -Doptimize=Debug|ReleaseSafe|ReleaseFast|ReleaseSmall (defaults to Debug).
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "subseeker",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Build and run subseeker");
    run_step.dependOn(&run_cmd.step);
}
