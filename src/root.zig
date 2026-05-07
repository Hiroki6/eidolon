const std = @import("std");
const windows = std.os.windows;

// Export PE module for external use
pub const pe = @import("pe.zig");

// Windows API definitions
const HMODULE = windows.HMODULE;
extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(.winapi) ?HMODULE;

/// Find the ROP gadget (jmp qword ptr [rbx], bytes 0xFF 0x23) in kernel32.dll
pub fn find_gadget() ?usize {
    const h_module_raw = GetModuleHandleA("kernel32.dll") orelse return null;
    const h_module = @as([*:0]u8, @ptrCast(h_module_raw));

    const dos_header: *pe.ImageDosHeader = @ptrCast(@alignCast(h_module));
    const nt_headers: *pe.ImageNtHeaders64 = @ptrCast(@alignCast(@as(*u8, @ptrFromInt(@intFromPtr(h_module) + @as(usize, @intCast(dos_header.e_lfanew))))));

    const size_of_image = nt_headers.OptionalHeader.SizeOfImage;
    const module_slice = h_module[0..size_of_image];

    const pattern = [_]u8{ 0xFF, 0x23 };
    if (std.mem.indexOf(u8, module_slice, &pattern)) |index| {
        return @intFromPtr(&module_slice[index]);
    }
    return null;
}

/// Configuration struct for stack spoofing
pub const StackConfig = extern struct {
    p_rop_gadget: usize,
    p_target: usize,
    arg_count: u32,
    p_ebx: usize,
    p_args: ?[*]usize,
    ret_addr: usize,

    pub fn init(allocator: std.mem.Allocator, p_rop_gadget: usize, p_target: usize, args: anytype) !StackConfig {
        const arg_count = args.len;
        var adjusted_count: u32 = if (arg_count > 4)
            @intCast(arg_count)
        else
            4;
        if (adjusted_count % 2 != 0) adjusted_count += 1;

        const buffer = try allocator.alloc(usize, adjusted_count);
        @memset(buffer, 0);

        inline for (args, 0..) |arg, i| {
            buffer[i] = switch (@typeInfo(@TypeOf(arg))) {
                .int, .comptime_int => @intCast(arg),
                .pointer => @intFromPtr(arg),
                .optional => if (arg) |ptr| @intFromPtr(ptr) else 0,
                .bool => @intFromBool(arg),
                .null => 0,
                else => @compileError("Unsupported type in StackConfig"),
            };
        }

        return StackConfig{
            .p_rop_gadget = p_rop_gadget,
            .p_target = p_target,
            .arg_count = adjusted_count,
            .p_ebx = 0,
            .p_args = buffer.ptr,
            .ret_addr = 0,
        };
    }
};

/// External assembly function that performs the actual stack spoofing
/// Returns the return value of the target function
pub extern fn Spoof(config: *StackConfig) callconv(.winapi) usize;
