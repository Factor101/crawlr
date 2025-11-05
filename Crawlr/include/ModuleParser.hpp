#pragma once
#include "Export.hpp"
#include "Module.hpp"
#include "Syscall.hpp"
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace Crawlr
{
namespace ModuleParser
{
    using namespace CrawlrNative;
    typedef struct Result
    {
        bool success;
        const std::string error;
        Module::MemoryInfo memoryInfo;
        std::map<const std::string, Export>& exports;
        std::map<const std::string, Syscall>& syscalls;
    };

    const LDR_DATA_TABLE_ENTRY* getModuleBase(const wchar_t* moduleName) noexcept;
    Module::MemoryInfo parseModuleMemory(const wchar_t* moduleName) noexcept;
    Result parseExports(const wchar_t* moduleName, const std::vector<const std::string>& targetNames = {});
    Result parseExportDirectory(void* moduleBase, const std::vector<const std::string>& targetNames = {});

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
