const std = @import("std");
const eidolon = @import("eidolon");

fn displayReturnAddress() callconv(.winapi) void {
    const ret_addr = @returnAddress();
    std.debug.print("Return address: 0x{x}\n", .{ret_addr});
}

export const jmp_rbx: [2]u8 linksection(".text") = .{ 0xFF, 0x23 };

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const gadget_addr = @intFromPtr(&jmp_rbx);
    _ = displayReturnAddress();
    _ = displayReturnAddress();
    const target_func_address = @intFromPtr(&displayReturnAddress);
    var foo_config = try eidolon.StackConfig.init(
        allocator,
        gadget_addr,
        target_func_address,
        .{}, // No arguments
    );
    _ = eidolon.Spoof(&foo_config);
    _ = eidolon.Spoof(&foo_config);
}
