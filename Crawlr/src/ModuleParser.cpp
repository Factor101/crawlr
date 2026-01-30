#include "../include/ModuleParser.hpp"
#include "../include/detail/DebugPrint.hpp"
#include "../include/detail/NativeDefs.hpp"

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

Module::MemoryInfo parseModuleMemory(const wchar_t* moduleName) noexcept
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
    const IMAGE_EXPORT_DIRECTORY* pExportDirectory =
        (IMAGE_EXPORT_DIRECTORY*)(baseAddress
                                  + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                        .VirtualAddress);

    return { dllBase, pExportDirectory, pOptionalHeader->SizeOfImage };
}

Result parseExports(Module& module, const std::vector<const std::string>& targetNames = {}) noexcept
{
    const Module::MemoryInfo memInfo = module.getMemoryInfo();
    if(memInfo.baseAddress == nullptr || memInfo.exportDirectory == nullptr)
    {
        return { false, "Module was not correctly loaded!", memInfo };
    }

    const uint8_t* pBase                     = (uint8_t*)memInfo.baseAddress;
    const IMAGE_EXPORT_DIRECTORY* pExportDir = memInfo.exportDirectory;
    const DWORD* pAddressOfFunctionsRVA      = (DWORD*)(pBase + pExportDir->AddressOfFunctions);
    const DWORD* pAddressOfNamesRVA          = (DWORD*)(pBase + pExportDir->AddressOfNames);
    const DWORD* pAddressOfNameOrdinalsRVA   = (DWORD*)(pBase + pExportDir->AddressOfNameOrdinals);
    const DWORD numberOfNames                = pExportDir->NumberOfNames;

    for(DWORD i = 0; i < numberOfNames; ++i)
    {
        // function name
        const DWORD dwFunctionNameRVA = pAddressOfNamesRVA[i];
        if(dwFunctionNameRVA == 0)
        {
            continue;
        }

        const char* pFunctionName = (char*)(pBase + dwFunctionNameRVA);
        if(pFunctionName == nullptr)
        {
            continue;
        }

        void* pFunctionBase = (void*)(pBase + pAddressOfFunctionsRVA[pAddressOfNameOrdinalsRVA[i]]);
        Export exp{ pFunctionBase };

        //TODO: Add runtime hashing for pFunctionName
        _DEBUG_PRINTF("[+] Found Export \"%s\": 0x%p\n", pFunctionName, pFunctionBase);
    }
}
}  // namespace ModuleParser
}  // namespace Crawlr
