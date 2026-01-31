#include "../include/SyscallParser.hpp"
#include "../include/Signature.hpp"
#include <type_traits>

namespace Crawlr
{
namespace SyscallParser
{
namespace
{
constexpr uint8_t SYSCALL_INSTRUCTION[] = "\x0F\x05";  // syscall
constexpr uint8_t JMP_INSTRUCTION       = 0xE9;
const Signature SYSCALL_SIGNATURE =
    "4C 8B D1 B8 ?? ?? ?? ?? 0F 05";  // mov r10, rcx; mov eax, ?? ?? ?? ?? syscall
}  // namespace

ScanResult scanExport(const Export& ex) noexcept
{
    ScanResult result{ false, false, nullptr };
    result.isSyscall =
        SYSCALL_SIGNATURE.matchesAt(static_cast<uint8_t*>(ex.getBaseAddress()), ex.getSize(), 0);

    if(!result.isSyscall)
    {
        return result;
    }

    uint8_t* pInvokeSyscall = firstSyscallInvocation(ex);
    DWORD ssn               = findSSN(ex, pInvokeSyscall);
}

// able to pass in void* or Export-derived class
template<typename T>
    requires std::is_base_of_v<Crawlr::Export, T>
uint8_t* firstSyscallInvocation(const T& ex) noexcept
{
    uint8_t* pBase = static_cast<uint8_t*>(ex.getBaseAddress());
    size_t size    = ex.getSize();
    size_t offset  = SYSCALL_SIGNATURE.matchFirst(pBase, size);  // find first syscall invocation

    if(offset != Signature::npos)
    {
        return pBase + offset;
    }

    return nullptr;
}

DWORD findSSN(const Export& ex, uint8_t* pInvokeSyscall)
{
    uint8_t* pBase = static_cast<uint8_t*>(ex.getBaseAddress());
    size_t size    = ex.getSize();
    if(pInvokeSyscall == nullptr)
    {
        return 0;
    }
    // parse for EAX value
    DWORD ssn = 0;
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

}  // namespace SyscallParser
}  // namespace Crawlr

