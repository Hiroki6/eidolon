.intel_syntax noprefix
.text
.global Spoof

# Config struct offsets (matching Zig extern struct StackConfig)
# p_rop_gadget: usize  (offset 0)
# p_target:     usize  (offset 8)
# arg_count:    u32    (offset 16, with 4 bytes padding)
# p_ebx:        usize  (offset 24)
# p_args:       ?[*]usize (offset 32)
# ret_addr:     usize  (offset 40)
.set Config_pRopGadget, 0
.set Config_pTarget, 8
.set Config_dwArgCount, 16
.set Config_pRbx, 24
.set Config_pArgs, 32
.set Config_retAddr, 40

Spoof:
    pop r11
    push rbx                                # save non-volatile registers
    push r12
    push r13
    push r15

    mov r10, rcx                            # address of Config, which is passed as an argument in rcx
    mov [r10 + Config_retAddr], r11         # store return address in config (survives target call)
    mov r12d, [r10 + Config_dwArgCount]     # number of arguments are stored in r12
    sub r12d, 4                             # no. of arguments on stack, as the first 4 are stored in registers
    mov r13, [r10 + Config_pArgs]           # args
    mov rcx, [r13]                          # first arg
    mov rdx, [r13 + 8]                      # second arg
    mov r8, [r13 + 16]                      # third arg
    mov r9, [r13 + 24]                      # fourth arg

    # Calculate the size of additional arguments
    shl r12, 3                              # r12 = r12 * 8
    sub rsp, r12                            # making space on the stack

.Lloop_start:
    cmp r12, 0                              # checking if the counter is zero
    jle .Lloop_end
    mov r15, rsp                            # copying stack pointer into temp variable
    add r15, r12                            # address where argument needs to be written
    sub r15, 8
    mov rax, [r13 + 24 + r12]               # copying argument into temp variable
    mov [r15], rax                          # writing argument on the stack
    sub r12, 8                              # decrementing the counter
    jmp .Lloop_start

.Lloop_end:
    mov r13d, [r10 + Config_dwArgCount]     # storing the argument count in a non-volatile register

    sub rsp, 32                             # shadow space

    mov rax, [r10 + Config_pRopGadget]      # copying return address to temp variable (Gadget's address)
    push rax                                # pushing the return address on the stack. RSP now ends in 8.

    lea rbx, [rip + .Lcleanup]              # setting the value of rbx. Rop gadget will jump to this address
    mov [r10 + Config_pRbx], rbx
    lea rbx, [r10 + Config_pRbx]
    mov r12, [r10 + Config_pTarget]
    jmp r12                                 # jumping to the target function

.Lcleanup:
    shl r13, 3                              # r13 = r13 * 8
    add rsp, r13                            # reverting stack to its original state
    pop r15                                 # restore non-volatile registers
    pop r13
    pop r12
    mov r11, [rbx + Config_retAddr - Config_pRbx]
    pop rbx
    jmp r11