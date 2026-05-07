const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const eidolon_mod = b.addModule("eidolon", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    eidolon_mod.addAssemblyFile(b.path("src/asm/spoof.s"));

    // Build examples
    const example_step = b.step("examples", "Build examples");
    for ([_][]const u8{
        "debug_return_address",
        "messagebox",
        "shellcode_injection",
    }) |example_name| {
        const example = b.addExecutable(.{
            .name = example_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("examples/{s}.zig", .{example_name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "eidolon", .module = eidolon_mod },
                },
            }),
        });
        const install_example = b.addInstallArtifact(example, .{});
        example_step.dependOn(&example.step);
        example_step.dependOn(&install_example.step);
    }

    const all_step = b.step("all", "Build everything");
    all_step.dependOn(example_step);

    // Tests
    const mod_tests = b.addTest(.{
        .root_module = eidolon_mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    b.default_step.dependOn(all_step);
}
