#pragma once
#include "Export.hpp"
#include "Module.hpp"
#include "Syscall.hpp"
#include <expected>
#include <functional>
#include <string>
#include <vector>

namespace Crawlr
{
namespace ModuleParser
{
using namespace CrawlrNative;

std::expected<Module::MemoryInfo, std::string> parseModuleMemoryInfo(
    const std::wstring& moduleName) noexcept;

std::expected<void, std::string> parseExports(
    Module& module,
    const std::vector<std::string>& targetNames = {}) noexcept;

std::expected<void, std::string> parseExports(
    Module& module,
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
