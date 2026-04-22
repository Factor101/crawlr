#include "../include/Syscall.hpp"

extern "C" __attribute__((naked)) uintptr_t invokeSyscall(
    uint32_t /*ssn*/, void* /*pSyscallOpcode*/,
    uintptr_t /*a1*/, uintptr_t /*a2*/, uintptr_t /*a3*/, uintptr_t /*a4*/,
    uintptr_t /*a5*/, uintptr_t /*a6*/, uintptr_t /*a7*/, uintptr_t /*a8*/
)
{
    asm(R"(
        mov eax, ecx         ; eax = ssn (x64 syscall abi mandates DWORD ssn -> eax)
        mov r11, rdx         ; r11 = pSyscallOpcode
        mov r10, r8          ; r10 = a1
        mov rdx, r9          ; rdx = a2
        mov r8, [rsp+0x28]   ;  r8 = a3
        mov r9, [rsp+0x30]   ;  r9 = a4

        mov [rsp+0x08], rax  ; rsp+0x08 = rax = ssn (preserve in shadow space)
        mov [rsp+0x10], r11  ; rsp+0x10 = r11 = pSyscallOpcode (preserve in shadow)

        mov rax, [rsp+0x38]  ; rax = a5 (5th arg @ rsp+0x28; a5 is 7th local arg)
        mov [rsp+0x28], rax  ; rsp+0x28 = a5

        mov rax, [rsp+0x40]  ; rax = a6
        mov [rsp+0x30], rax  ; rsp+0x30 = a6

        mov rax, [rsp+0x48]  ; rax = a7
        mov [rsp+0x38], rax  ; rsp+0x38 = a7
        mov rax, [rsp+0x50]  ; rax = a8
        mov [rsp+0x40], rax  ; rsp+0x38 = a8
        xor rax, rax         ; clear rax high bits
        mov eax, [rsp+0x08]  ; restore eax to ssn value

        jmp r11              ; jump to address of syscall invocation
;   --> syscall
;       ret                  <-- return handled for us
    )");
}
