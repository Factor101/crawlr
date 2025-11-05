#include "../include/ModuleParser.hpp"
#include "../include/detail/NativeDefs.hpp"
#define OFFSET(t_struct, field) (uint64_t)(&((t_struct*)nullptr)->field)

namespace Crawlr
{
namespace ModuleParser
{
    using namespace CrawlrNative;
    const LDR_DATA_TABLE_ENTRY* getModuleEntry(const wchar_t* moduleName) noexcept
    {
        static const LIST_ENTRY* pModuleListHead = getModuleListHead();

        for(LIST_ENTRY* node = pModuleListHead->Flink; node != pModuleListHead; node = node->Flink)
        {
            // InMemoryOrderLinks = 2nd of 1st 2 entries type LIST_ENTRY;
            //      = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            // const LDR_DATA_TABLE_ENTRY* pTableEntry
            //      = (LDR_DATA_TABLE_ENTRY*)((uint8_t*)node - sizeof(LIST_ENTRY));
            const LDR_DATA_TABLE_ENTRY* pTableEntry =
                (LDR_DATA_TABLE_ENTRY*)((uint8_t*)node - OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

            if(pTableEntry->DllBase == nullptr)
            {
                continue;
            }

            //TODO: Hash dll name
            if(wcscmp(moduleName, pTableEntry->BaseDllName.Buffer) == 0)
            {
                return pTableEntry;
            }
        }

        return nullptr;
    }

    Module::MemoryInfo parseModuleMemory(const wchar_t* moduleName) noexcept
    {
        Module::MemoryInfo memoryInfo{ nullptr, nullptr };
        const void* dllBase;
        if(const LDR_DATA_TABLE_ENTRY* pLdrEntry = getModuleEntry(moduleName); pLdrEntry != nullptr)
        {
            dllBase = pLdrEntry->DllBase;
        }
        else
        {
            dllBase = nullptr;
        }

        memoryInfo.baseAddress                 = (uint8_t*)dllBase;
        IMAGE_DOS_HEADER* pDosHeader           = (IMAGE_DOS_HEADER*)memoryInfo.baseAddress;
        IMAGE_NT_HEADERS* pNtHeaders           = (IMAGE_NT_HEADERS*)(memoryInfo.baseAddress + pDosHeader->e_lfanew);
        IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeaders->OptionalHeader;
        memoryInfo.exportDirectory =
            (PIMAGE_EXPORT_DIRECTORY)(memoryInfo.baseAddress
                                      + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        return memoryInfo;
    }
    Result parseExports(const wchar_t* moduleName, const std::vector<const std::string>& targetNames = {});
    Result parseExportDirectory(void* moduleBase, const std::vector<const std::string>& targetNames = {});
}  // namespace ModuleParser
}  // namespace Crawlr
