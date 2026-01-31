#include "../include/ModuleParser.hpp"
#include "../include/detail/DebugPrint.hpp"
#include "../include/detail/NativeDefs.hpp"
#include <algorithm>

#define OFFSET(t_struct, field) (uint64_t)(&((t_struct*)nullptr)->field)

namespace Crawlr
{
namespace ModuleParser
{
using namespace CrawlrNative;
const LDR_DATA_TABLE_ENTRY* getModuleEntry(const wchar_t* moduleName) noexcept
{
    // PEB list head location is volatile; do not cache/make static
    const LIST_ENTRY* pModuleListHead = getModuleListHead();

    for(LIST_ENTRY* node = pModuleListHead->Flink; node != pModuleListHead; node = node->Flink)
    {
        // InMemoryOrderLinks = 2nd of 1st 2 entries type LIST_ENTRY;
        //      = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        // const LDR_DATA_TABLE_ENTRY* pTableEntry
        //      = (LDR_DATA_TABLE_ENTRY*)((uint8_t*)node - sizeof(LIST_ENTRY));
        const LDR_DATA_TABLE_ENTRY* pTableEntry =
            (LDR_DATA_TABLE_ENTRY*)((uint8_t*)node
                                    - OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

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

Module::MemoryInfo parseModuleMemoryInfo(const wchar_t* moduleName) noexcept
{
    const void* dllBase;
    if(const LDR_DATA_TABLE_ENTRY* pLdrEntry = getModuleEntry(moduleName); pLdrEntry != nullptr)
    {
        dllBase = pLdrEntry->DllBase;
    }
    else
    {
        return { nullptr, nullptr, 0 };
    }

    const uint8_t* baseAddress         = (uint8_t*)dllBase;
    const IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)baseAddress;
    const IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(baseAddress + pDosHeader->e_lfanew);
    const IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeaders->OptionalHeader;
    const uint32_t exportDirRVA =
        pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if(exportDirRVA == 0)
    {
        return { dllBase, nullptr, pOptionalHeader->SizeOfImage };
    }

    const IMAGE_EXPORT_DIRECTORY* pExportDirectory =
        (IMAGE_EXPORT_DIRECTORY*)(baseAddress + exportDirRVA);

    return { dllBase, pExportDirectory, pOptionalHeader->SizeOfImage };
}

ExportsParseResult parseExports(Module& module,
                                const std::vector<std::string>& targetNames = {}) noexcept
{
    auto defaultNameFilter = [&targetNames](const char* exportName) -> bool {
        return targetNames.empty()
            || std::find_if(targetNames.begin(),
                            targetNames.end(),
                            [exportName](const std::string& name) { return name == exportName; })
                   != targetNames.end();
    };

    return parseExports(module, defaultNameFilter);
}

ExportsParseResult parseExports(Module& module,
                                std::function<bool(const char* exportName)> nameFilter) noexcept
{
    const Module::MemoryInfo memInfo = module.getMemoryInfo();
    if(memInfo.baseAddress == nullptr || memInfo.exportDirectory == nullptr)
    {
        return { false, "Attempted to parse exports of module with invalid memory info." };
    }

    const uint8_t* pBase                     = (uint8_t*)memInfo.baseAddress;
    const IMAGE_EXPORT_DIRECTORY* pExportDir = memInfo.exportDirectory;
    const DWORD* pAddressOfFunctionsRVA      = (DWORD*)(pBase + pExportDir->AddressOfFunctions);
    const DWORD* pAddressOfNamesRVA          = (DWORD*)(pBase + pExportDir->AddressOfNames);
    const WORD* pAddressOfNameOrdinalsRVA    = (WORD*)(pBase + pExportDir->AddressOfNameOrdinals);
    const DWORD numberOfNames                = pExportDir->NumberOfNames;

    for(DWORD i = 0; i < numberOfNames; ++i)
    {
        // function name
        const DWORD dwFunctionNameRVA = pAddressOfNamesRVA[i];
        if(dwFunctionNameRVA == 0)
        {
            continue;
        }

        const char* pExportName = (char*)(pBase + dwFunctionNameRVA);

        if(!nameFilter(pExportName))
        {
            continue;
        }

        uint32_t rva = pAddressOfFunctionsRVA[pAddressOfNameOrdinalsRVA[i]];

        //TODO : Handle forwarded exports (validate rva within export dir range)
        void* pEntryBase = (void*)(pBase + rva);

        // Calculate the size of the export function.
        // We cannot simply calculate against i + 1 since AddressOfFunctions is
        // indexed by ordinal, not by memory location.
        uint32_t nextHighestRVA = memInfo.imageSize;  // Default to image size
        for(DWORD j = 0; j < pExportDir->NumberOfFunctions; ++j)
        {
            uint32_t candidateRVA = pAddressOfFunctionsRVA[j];
            if(candidateRVA > rva && candidateRVA < nextHighestRVA)
            {
                nextHighestRVA = candidateRVA;
            }
        }
        uint32_t exportSize = nextHighestRVA - rva;

        //TODO: Add runtime hashing for pExportName
        module.addExport(std::string(pExportName), Export{ pEntryBase, rva, exportSize });
        _DEBUG_PRINTF("[+] Found Export \"%s\": 0x%p Size 0x%X\n",
                      pExportName,
                      pEntryBase,
                      exportSize);
    }

    return { true, "" };
}

}  // namespace ModuleParser
}  // namespace Crawlr

#undef OFFSET
