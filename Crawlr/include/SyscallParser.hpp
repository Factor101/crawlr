#pragma once

#include "Export.hpp"
#include "Syscall.hpp"
#include "./detail/NativeDefs.hpp"

namespace Crawlr
{
namespace SyscallParser
{
typedef struct ScanResult
{
    bool isSyscall;
    bool isHooked;
    void* pSyscallOpcode;
};

ScanResult scanExport(const Export& exp) noexcept;

template<typename T>
DWORD* scanSyscallOpAddress(const T& exp) noexcept;
}

namespace
{
    inline
}
}
