#include "../include/SyscallParser.hpp"
#include <type_traits>

namespace Crawlr
{
namespace SyscallParser
{
namespace
{
constexpr uint8_t SYSCALL_INSTRUCTION[] = "\x0F\x05";          // syscall
constexpr uint8_t JMP_INSTRUCTION       = 0xE9;
constexpr uint8_t SYSCALL_SIGNATURE[]   = "\x4C\x8B\xD1\xB8";  // mov r10, rcx; mov eax, ?? ??

typedef struct ExportLocation
{
    void* pBase;
    ULONG size;
};
}  // namespace

ScanResult scanExport(const Export& ex) noexcept
{
    ScanResult result{ false, false, nullptr };
    uint8_t* pInvokeSyscall = findSyscallByte(ex);
    DWORD ssn               = findSSN(ex, pInvokeSyscall);
constexpr uint8_t SYSCALL_INSTRUCTION[] = "\x0F\x05";          // syscall
constexpr uint8_t JMP_INSTRUCTION       = 0xE9;                // 4C 8B D1 B8 ?? ?? ?? ?? 0F 05
constexpr uint8_t SYSCALL_SIGNATURE[]   = "\x4C\x8B\xD1\xB8";  // mov r10, rcx; mov eax, ?? ??
}  // namespace

ScanResult scanExport(const Export& ex) noexcept
{
    ScanResult result{ false, false, nullptr };
    uint8_t* pInvokeSyscall = findSyscallByte(ex);
    DWORD ssn               = findSSN(ex, pInvokeSyscall);
}

// able to pass in void* or Export-derived class
template<typename T>
    requires std::is_base_of_v<Crawlr::Export, T>
uint8_t* firstSyscallInvoke(const T& ex) noexcept
{
    const ULONG size = ex.getSize();
    for(DWORD i = 0; i < size; ++i)
    {
        uint8_t* pCurrentByte = (uint8_t*)ex.getBaseAddress() + i;
        if(*(uint8_t*)pCurrentByte == SYSCALL_SIGNATURE[0]
           && *(uint8_t*)(pCurrentByte + 1) == SYSCALL_SIGNATURE[1])
        {
            return (DWORD*)pCurrentByte;
        }
    }

    return nullptr;
}

DWORD findSSN(const Export& ex, uint8_t* pInvokeSyscall)
{
	void* pBase = ex.getBaseAddress();
    if(*(uint8_t*)pBase == JMP_INSTRUCTION)
    {
        // function is hooked
    }
    else
    {
        // ssn must be pFunctionBase + 0x04
        return *(uint8_t*)((uint8_t*)pBase + 0x04);
    }
}

bool detectHooks(const Export& ex)
{

    // detect Bitdefender EDR hook
    // if first byte is JMP, then function is hooked
    if(*(uint8_t*)ex.getBaseAddress() == 0xE9)
    {
        // e9 0b 02 18 00 == jmp QWORD PTR
        // E9 ?? ?? ?? ?? == sig

        // check surround exports
        // ntdll exports are spaced 0x20 bytes apart
        PVOID pPrevExport = (PBYTE)pFunctionBase - 0x20;
        PVOID pNextExport = (PBYTE)pFunctionBase + 0x20;


        return 0;
    }

    return FALSE;
}
}  // namespace SyscallParser
}  // namespace SyscallParser

}  // namespace Crawlr


__forceinline _NODISCARD DWORD Syscall::getSSN(PVOID pFunctionBase)
{
    constexpr BYTE syscallSignature[] = {
        0x4c,
        0x8b,
        0xd1,  // mov r10, rcx
        0xb8,  // mov eax, ? ? ? ?
    };


    // parse for EAX value

    BYTE ssn = 0;
    for(auto i = 0; i < 0x20; i++)
    {
        PBYTE pCurrentByte = (PBYTE)pFunctionBase + i;
        if(memcmp(pCurrentByte, syscallSignature, sizeof(syscallSignature)) == 0)
        {
            ssn = *(PBYTE)(pCurrentByte + sizeof(syscallSignature));
            break;
        }
    }


    return ssn;
}
    constexpr BYTE syscallSignature[] = {
        0x4c,
        0x8b,
        0xd1,  // mov r10, rcx
        0xb8,  // mov eax, ? ? ? ?
    };


    // parse for EAX value

    BYTE ssn = 0;
    for(auto i = 0; i < 0x20; i++)
    {
        PBYTE pCurrentByte = (PBYTE)pFunctionBase + i;
        if(memcmp(pCurrentByte, syscallSignature, sizeof(syscallSignature)) == 0)
        {
            ssn = *(PBYTE)(pCurrentByte + sizeof(syscallSignature));
            break;
        }
    }


    return ssn;
}
