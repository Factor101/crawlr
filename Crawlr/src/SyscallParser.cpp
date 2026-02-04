#include "../include/SyscallParser.hpp"
#include "../include/Signature.hpp"

namespace Crawlr
{
namespace SyscallParser
{
namespace
{
constexpr uint8_t SYSCALL_OPCODE[] = { 0x0F, 0x05 };  // syscall instruction opcode
const Signature SYSCALL_SIGNATURE =
    "4C 8B D1 B8 ?? ?? ?? ?? 0F 05";                  // mov r10, rcx; mov eax, ?? ?? ?? ?? syscall
constexpr auto SYSCALL_INVOCATION_OFFSET = 8;
constexpr auto SYSCALL_NUMBER_OFFSET     = 4;
}  // namespace

[[nodiscard]] ScanResult scanExport(const Export& exp) noexcept
{
    ScanResult result{ false, false, nullptr, 0 };
    uint8_t* pBase = static_cast<uint8_t*>(exp.getBaseAddress());
    if(pBase == nullptr || exp.getSize() < SYSCALL_SIGNATURE.size())
    {
        return result;
    }

    result.isSyscall =
        memcmp(pBase + SYSCALL_INVOCATION_OFFSET, SYSCALL_OPCODE, sizeof(SYSCALL_OPCODE)) == 0;

    if(!result.isSyscall)
    {
        return result;
    }

    result.matchesUnhookedSyscall = SYSCALL_SIGNATURE.matches(pBase, exp.getSize());

    if(!result.matchesUnhookedSyscall)
    {
        return result;
    }

    result.pSyscallOpcode = pBase + SYSCALL_INVOCATION_OFFSET;
    result.syscallNumber  = *reinterpret_cast<DWORD*>(pBase + SYSCALL_NUMBER_OFFSET);

    return result;
}
}  // namespace SyscallParser
}  // namespace Crawlr
