#pragma once
#include "Export.hpp"
#include "Module.hpp"
#include "Syscall.hpp"
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace Crawlr
{
namespace ModuleParser
{
using namespace CrawlrNative;

typedef struct ModuleParseResult
{
    bool success;
    std::string error;
    Module::MemoryInfo memoryInfo;
};

typedef struct ExportsParseResult
{
    bool success;
    std::string error;
};

const LDR_DATA_TABLE_ENTRY* getModuleEntry(const wchar_t* moduleName) noexcept;
Module::MemoryInfo parseModuleMemoryInfo(const wchar_t* moduleName) noexcept;

ExportsParseResult parseExports(Module& module,
                                const std::vector<std::string>& targetNames = {}) noexcept;
ExportsParseResult parseExports(Module& module,
                                std::function<bool(const char* exportName)> nameFilter) noexcept;
namespace
{
inline LIST_ENTRY* getModuleListHead() noexcept
{
    PEB* peb;
    asm("mov %[ppeb], gs:[0x60]"
        : [ppeb] "=r"(peb));

    LIST_ENTRY* pModuleListHead = &peb->Ldr->InMemoryOrderModuleList;

    return pModuleListHead;
}
}  // namespace
}  // namespace ModuleParser
}  // namespace Crawlr
