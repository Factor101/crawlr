#pragma once

#include "./detail/NativeDefs.hpp"
#include "Export.hpp"
#include "Syscall.hpp"
#include <concepts>

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

ScanResult scanExport(const Export& ex) noexcept;

// template<typename T>
// concept ModuleExport = std::is_base_of_v<Crawlr::Export, T>;

template<typename T>
    requires std::is_base_of_v<Crawlr::Export, T>
uint8_t* firstSyscallInvocation(const T& ex) noexcept;
}  // namespace SyscallParser
}  // namespace Crawlr
