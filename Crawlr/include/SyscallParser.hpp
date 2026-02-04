#pragma once

#include "./detail/NativeDefs.hpp"
#include "Export.hpp"
#include "Syscall.hpp"

namespace Crawlr
{
namespace SyscallParser
{
typedef struct ScanResult
{
    bool isSyscall;
    bool matchesUnhookedSyscall;
    void* pSyscallOpcode;
    DWORD syscallNumber;  // aka SSN
};


[[nodiscard]] ScanResult scanExport(const Export& exp) noexcept;
}  // namespace SyscallParser
}  // namespace Crawlr
