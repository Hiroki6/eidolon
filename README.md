# Eidolon

Return address spoofing library for Windows x64, implemented in Zig.

Eidolon implements a return address spoofing technique that makes Windows API calls appear to originate from legitimate modules (like `kernel32.dll`) instead of your executable. This bypasses stack-based security detection mechanisms used by EDR and antivirus software.

[Read the technical deep dive on the implementation here.](https://hiroki6.dev/posts/return-address-spoofing-in-zig/)

## Quick Start

### Installation
Add to your `build.zig.zon`:

```
zig fetch --save git+https://github.com/Hiroki6/eidolon
```

Then in your build.zig:

```zig
const eidolon = b.dependency("eidolon", .{});
exe.root_module.addImport("eidolon", zcircuit.module("eidolon"));
```

### Example Usage

```zig
const std = @import("std");
const eidolon = @import("eidolon");

// Target function MUST use .winapi calling convention
fn your_function(arg1: usize, arg2: usize, arg3: usize) callconv(.winapi) usize {
    // Your code here
    return 0;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Find ROP gadget in kernel32.dll
    const gadget = eidolon.find_gadget() orelse return error.NoGadget;

    // Setup configuration
    var config = try eidolon.StackConfig.init(
        allocator,
        gadget,
        @intFromPtr(&your_function),
        .{ arg1, arg2, arg3 }, // Function arguments
    );
    defer allocator.free(config.p_args.?[0..config.arg_count]);

    // Execute with spoofed return address
    const result = eidolon.Spoof(&config);
}
```

**Important:** The target function must use `callconv(.winapi)` to ensure proper Windows x64 calling convention compatibility.

## References

- [x64 Return Address Spoofing](https://hulkops.gitbook.io/blog/red-team/x64-return-address-spoofing)
- [The Stack Series: Return Address Spoofing on x64](https://sabotagesec.com/the-stack-series-return-address-spoofing-on-x64/)
- [Return Address Spoofing in Zig](https://hiroki6.dev/posts/return-address-spoofing-in-zig/)

## Legal Disclaimer

This tool is for educational purposes and authorized security auditing only. The author is not responsible for any misuse of this software.
