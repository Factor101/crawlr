#pragma once

#include "./detail/NativeDefs.hpp"
#include "Export.hpp"
#include "Syscall.hpp"

namespace Crawlr
{
namespace SyscallParser
{
struct ScanResult
{
    bool isSyscall;
    bool matchesUnhookedSyscall;
    void* pSyscallOpcode;
    uint32_t syscallNumber;  // aka SSN
};


[[nodiscard]] ScanResult scanExport(const Export& exp) noexcept;
}  // namespace SyscallParser
}  // namespace Crawlr
