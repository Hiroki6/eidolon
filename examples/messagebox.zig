const std = @import("std");
const eidolon = @import("eidolon");

const win = std.os.windows;

// MessageBox constants
const MB_OK = 0x00000000;
const MB_ICONINFORMATION = 0x00000040;

// Windows API declarations
extern "kernel32" fn LoadLibraryA(lpLibFileName: [*:0]const u8) callconv(.winapi) ?win.HINSTANCE;
extern "kernel32" fn GetProcAddress(hModule: ?win.HINSTANCE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.debug.print("[*] MessageBox with Return Address Spoofing\n\n", .{});

    // Find the ROP gadget in kernel32.dll
    const gadget = eidolon.find_gadget() orelse {
        std.debug.print("[-] Failed to find ROP gadget\n", .{});
        return error.GadgetNotFound;
    };
    std.debug.print("[+] Found ROP gadget at: 0x{X}\n", .{gadget});

    // Load user32.dll and get MessageBoxA address
    const user32 = LoadLibraryA("user32.dll") orelse {
        std.debug.print("[-] Failed to load user32.dll\n", .{});
        return error.LoadLibraryFailed;
    };
    std.debug.print("[+] Loaded user32.dll at: 0x{X}\n", .{@intFromPtr(user32)});

    const messagebox_addr = @intFromPtr(GetProcAddress(user32, "MessageBoxA") orelse {
        std.debug.print("[-] Failed to get MessageBoxA address\n", .{});
        return error.GetProcAddressFailed;
    });
    std.debug.print("[+] MessageBoxA at: 0x{X}\n", .{messagebox_addr});

    const message = "This MessageBox was called with a spoofed return address!";
    const caption = "Eidolon Demo";

    // Create StackConfig for MessageBoxA
    var messagebox_config = try eidolon.StackConfig.init(
        allocator,
        gadget,
        messagebox_addr,
        .{
            @as(usize, 0), // hWnd (null)
            @intFromPtr(message.ptr), // lpText
            @intFromPtr(caption.ptr), // lpCaption
            @as(usize, MB_OK | MB_ICONINFORMATION), // uType
        },
    );
    defer allocator.free(messagebox_config.p_args.?[0..messagebox_config.arg_count]);

    std.debug.print("[*] Calling MessageBoxA with spoofed return address...\n", .{});
    std.debug.print("[!] The call stack will show kernel32.dll as the caller\n\n", .{});

    // Call MessageBoxA with spoofed return address
    const result = eidolon.Spoof(&messagebox_config);

    std.debug.print("[+] MessageBox returned: {}\n", .{result});
    std.debug.print("Successfully called MessageBox with spoofed return address!\n", .{});
}
