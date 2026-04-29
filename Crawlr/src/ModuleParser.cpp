#include "../include/ModuleParser.hpp"
#include "../include/SyscallParser.hpp"
#include "../include/detail/DebugPrint.hpp"
#include "../include/detail/NativeDefs.hpp"
#include <algorithm>
#include <cstring>
#include <format>
#include <utility>

#define CRAWLR_OFFSET(t_struct, field) (uint64_t)(&((t_struct*)nullptr)->field)

namespace Crawlr
{
namespace ModuleParser
{
using namespace CrawlrNative;
namespace  // Forward declarations for internal functions/structures
{

struct ReadExportDirResult
{
    bool success;
    std::string errorTemplate;
    uint32_t exportDirRva;
    uint32_t exportDirSize;
};

ReadExportDirResult tryGetExportDirectoryInfo(const uint8_t* base,
                                              uint32_t imageSize,
                                              const std::wstring& moduleName) noexcept;

const LDR_DATA_TABLE_ENTRY* getModuleEntry(const std::wstring& moduleName) noexcept;

std::vector<uint32_t> getSortedExportRVAs(const uint8_t* pBase,
                                          const IMAGE_EXPORT_DIRECTORY* pExportDir,
                                          uint32_t imageSize) noexcept;
uint32_t calculateExportSize(uint32_t rva,
                             const std::vector<uint32_t>& sortedExportRVAs,
                             uint32_t imageSize) noexcept;

inline bool isValidRvaRange(uint32_t rva, uint32_t size, uint32_t imageSize) noexcept;

bool isValidRvaTableRange(uint32_t tableRVA,
                          uint32_t count,
                          uint32_t elementSize,
                          uint32_t imageSize) noexcept;

bool isValidCStringRva(uint32_t rva, const uint8_t* base, uint32_t imageSize) noexcept;
}  // namespace


std::expected<Module::MemoryInfo, std::string> parseModuleMemoryInfo(
    const std::wstring& moduleName) noexcept
{
    Module::MemoryInfo memInfo{};
    if(const LDR_DATA_TABLE_ENTRY* pLdrEntry = getModuleEntry(moduleName);
       pLdrEntry != nullptr)
    {
        memInfo.baseAddress = pLdrEntry->DllBase;
    }
    else
    {
        const std::wstring werr =
            std::format(L"Could not locate base address of '{}'", moduleName);
        return std::unexpected(std::string(werr.begin(), werr.end()));
    }

    const uint8_t* baseAddress = reinterpret_cast<const uint8_t*>(memInfo.baseAddress);
    const IMAGE_DOS_HEADER* pDosHeader =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(baseAddress);

    // Validate DOS header.
    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE
       || std::cmp_less(pDosHeader->e_lfanew, sizeof(IMAGE_DOS_HEADER)))
    {
        const std::wstring werr =
            std::format(L"Module '{}' contained invalid DOS headers", moduleName);
        return std::unexpected(std::string(werr.begin(), werr.end()));
    }

    // Validate NT headers.
    const IMAGE_NT_HEADERS* pNtHeaders =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(baseAddress + pDosHeader->e_lfanew);
    if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        const std::wstring werr =
            std::format(L"Module '{}' contained invalid NT headers", moduleName);
        return std::unexpected(std::string(werr.begin(), werr.end()));
    }

    // Validate Optional header.
    const IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeaders->OptionalHeader;
    if(pOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC
       || pOptionalHeader->SizeOfImage == 0)
    {
        const std::wstring werr =
            std::format(L"Module '{}' contained an invalid optional header", moduleName);
        return std::unexpected(std::string(werr.begin(), werr.end()));
    }

    // Validate image size.
    memInfo.imageSize = pOptionalHeader->SizeOfImage;
    if(std::cmp_greater_equal(pDosHeader->e_lfanew, memInfo.imageSize)
       || std::cmp_greater(pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS),
                           memInfo.imageSize))
    {
        const std::wstring werr =
            std::format(L"Module '{}' has invalid bounds", moduleName);
        return std::unexpected(std::string(werr.begin(), werr.end()));
    }

    // Try to get export directory info.
    ReadExportDirResult resExportDir =
        tryGetExportDirectoryInfo(baseAddress, memInfo.imageSize, moduleName);

    if(!resExportDir.success)
    {
        return std::unexpected(resExportDir.errorTemplate);
    }

    memInfo.exportDirRva    = resExportDir.exportDirRva;
    memInfo.exportDirSize   = resExportDir.exportDirSize;
    memInfo.exportDirectory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        baseAddress + resExportDir.exportDirRva);

    return memInfo;
}

std::expected<void, std::string> parseExports(
    Module& module,
    const std::vector<std::string>& exportNames) noexcept
{
    auto defaultNameFilter = [&exportNames](const char* exportName) -> bool {
        return exportNames.empty()
            || std::find_if(
                   exportNames.begin(),
                   exportNames.end(),
                   [exportName](const std::string& name) { return name == exportName; })
                   != exportNames.end();
    };

    return parseExports(module, defaultNameFilter);
}


std::expected<void, std::string> parseExports(
    Module& module,
    std::function<bool(const char* exportName)> nameFilter) noexcept
{
    //TODO : Handle forwarded exports properly
    //TODO: Add runtime hashing for pExportName
    const Module::MemoryInfo memInfo = module.getMemoryInfo();
    if(memInfo.baseAddress == nullptr || memInfo.exportDirectory == nullptr)
    {
        return std::unexpected(std::string(
            "Attempted to parse exports of module with invalid memory info."));
    }

    const uint8_t* pBase = reinterpret_cast<const uint8_t*>(memInfo.baseAddress);

    // Validate export directory tables' bounds.
    if(!isValidRvaTableRange(memInfo.exportDirectory->AddressOfFunctions,
                             memInfo.exportDirectory->NumberOfFunctions,
                             sizeof(DWORD),
                             memInfo.imageSize)
       || !isValidRvaTableRange(memInfo.exportDirectory->AddressOfNames,
                                memInfo.exportDirectory->NumberOfNames,
                                sizeof(DWORD),
                                memInfo.imageSize)
       || !isValidRvaTableRange(memInfo.exportDirectory->AddressOfNameOrdinals,
                                memInfo.exportDirectory->NumberOfNames,
                                sizeof(WORD),
                                memInfo.imageSize))
    {
        return std::unexpected(
            std::string("Export directory tables are out of image bounds."));
    }

    const DWORD* pAddressOfFunctions = reinterpret_cast<const DWORD*>(
        pBase + memInfo.exportDirectory->AddressOfFunctions);
    const DWORD* pAddressOfNames =
        reinterpret_cast<const DWORD*>(pBase + memInfo.exportDirectory->AddressOfNames);
    const WORD* pAddressOfNameOrdinals = reinterpret_cast<const WORD*>(
        pBase + memInfo.exportDirectory->AddressOfNameOrdinals);
    const DWORD numberOfNames = memInfo.exportDirectory->NumberOfNames;

    // We cannot simply calculate against i + 1 since AddressOfFunctions is
    // indexed by ordinal, not by memory location. Therefore, we build a sorted
    // list of all export RVAs to calculate export sizes correctly.
    const std::vector<uint32_t> sortedExportRVAs =
        getSortedExportRVAs(pBase, memInfo.exportDirectory, memInfo.imageSize);

    for(DWORD i = 0; i < numberOfNames; ++i)
    {
        // Get and validate null-terminated export name cstring.
        const DWORD functionNameRVA = pAddressOfNames[i];
        if(functionNameRVA == 0
           || !isValidCStringRva(functionNameRVA, pBase, memInfo.imageSize))
        {
            continue;
        }

        const char* pExportName = reinterpret_cast<const char*>(pBase + functionNameRVA);

        if(!nameFilter(pExportName))
        {
            continue;
        }

        // Get ordinal and validate that is within bounds.
        const WORD ordinal = pAddressOfNameOrdinals[i];
        if(ordinal >= memInfo.exportDirectory->NumberOfFunctions)
        {
            continue;
        }

        // Get function's RVA and validate.
        uint32_t rva = pAddressOfFunctions[ordinal];
        if(rva == 0 || rva >= memInfo.imageSize)
        {
            continue;
        }

        // Perform a rudimentary check for forwarded exports. //TODO: Handle properly.
        if(memInfo.exportDirSize != 0 && rva >= memInfo.exportDirRva
           && rva < (memInfo.exportDirRva + memInfo.exportDirSize))
        {
            continue;  // forwarded export
        }

        uint32_t exportSize =
            calculateExportSize(rva, sortedExportRVAs, memInfo.imageSize);

        // const_cast is needed in case we want to later remap the export's base address.
        void* pEntryBase = reinterpret_cast<void*>(const_cast<uint8_t*>(pBase + rva));

        //TODO: Handle hooked syscalls properly
        Export exp{ pEntryBase, rva, exportSize };
        if(SyscallParser::ScanResult scan = SyscallParser::scanExport(exp);
           scan.isSyscall && scan.matchesUnhookedSyscall)
        {
            module.addSyscall(
                std::string(pExportName),  // TODO: runtime string encryption
                Syscall{ pEntryBase,
                         rva,
                         exportSize,
                         scan.syscallNumber,
                         scan.pSyscallOpcode });

            _DEBUG_PRINTF("[+] Found Syscall \"%s\": SSN=0x%X opcode=%p\n",
                          pExportName,
                          scan.syscallNumber,
                          scan.pSyscallOpcode);
        }
        else
        {
            module.addExport(std::string(pExportName), exp);
            _DEBUG_PRINTF("[+] Found Export \"%s\": 0x%p Size 0x%X\n",
                          pExportName,
                          pEntryBase,
                          exportSize);
        }
    }

    return std::expected<void, std::string>{};
}

namespace
{
using namespace CrawlrNative;
inline LIST_ENTRY* getModuleListHead() noexcept
{
    PEB* peb;
    asm("mov %[ppeb], gs:[0x60]"
        : [ppeb] "=r"(peb));

    LIST_ENTRY* pModuleListHead = &peb->Ldr->InMemoryOrderModuleList;

    return pModuleListHead;
}

const LDR_DATA_TABLE_ENTRY* getModuleEntry(const std::wstring& moduleName) noexcept
{
    // PEB list head location is volatile; do not cache/make static
    const LIST_ENTRY* pModuleListHead = getModuleListHead();

    for(LIST_ENTRY* node = pModuleListHead->Flink; node != pModuleListHead;
        node             = node->Flink)
    {
        // InMemoryOrderLinks = 2nd of 1st 2 entries type LIST_ENTRY;
        //      = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        const LDR_DATA_TABLE_ENTRY* pTableEntry =
            reinterpret_cast<const LDR_DATA_TABLE_ENTRY*>(
                reinterpret_cast<uint8_t*>(node)
                - CRAWLR_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        if(pTableEntry->DllBase == nullptr || pTableEntry->BaseDllName.Buffer == nullptr)
        {
            continue;
        }

        //TODO: Hash dll name
        if(wcscmp(moduleName.data(), pTableEntry->BaseDllName.Buffer) == 0)
        {
            return pTableEntry;
        }
    }

    return nullptr;
}

ReadExportDirResult tryGetExportDirectoryInfo(const uint8_t* base,
                                              uint32_t imageSize,
                                              const std::wstring& moduleName) noexcept
{
    ReadExportDirResult res{ false, "", 0, 0 };

    // (!) We assume caller-enforced validation of DOS/NT headers and imageSize.
    const IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const IMAGE_NT_HEADERS* pNtHeaders =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(base + pDosHeader->e_lfanew);
    const IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeaders->OptionalHeader;

    res.exportDirRva =
        pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    res.exportDirSize = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // Validate export directory is not empty and has valid RVA.
    if(res.exportDirRva == 0 || res.exportDirSize == 0)
    {
        const std::wstring werr =
            std::format(L"Module '{}' has an empty export directory", moduleName);
        res.errorTemplate = std::string(werr.begin(), werr.end());
        return res;
    }
    else if(!isValidRvaRange(res.exportDirRva, res.exportDirSize, imageSize))
    {
        const std::wstring werr =
            std::format(L"The export directory of Module '{}' has invalid bounds",
                        moduleName);
        res.errorTemplate = std::string(werr.begin(), werr.end());
        return res;
    }

    res.success = true;

    return res;
}

std::vector<uint32_t> getSortedExportRVAs(const uint8_t* pBase,
                                          const IMAGE_EXPORT_DIRECTORY* pExportDir,
                                          uint32_t imageSize) noexcept
{
    std::vector<uint32_t> exportRVAs;
    const DWORD* pAddressOfFunctions =
        reinterpret_cast<const DWORD*>(pBase + pExportDir->AddressOfFunctions);

    for(DWORD i = 0; i < pExportDir->NumberOfFunctions; ++i)
    {
        if(uint32_t rva = pAddressOfFunctions[i]; rva != 0 && rva < imageSize)
        {
            exportRVAs.push_back(rva);
        }
    }

    std::sort(exportRVAs.begin(), exportRVAs.end());

    return exportRVAs;
}

uint32_t calculateExportSize(uint32_t rva,
                             const std::vector<uint32_t>& sortedExportRVAs,
                             uint32_t imageSize) noexcept
{
    if(rva >= imageSize)
    {
        return 0;
    }

    uint32_t nextHighestRVA = imageSize;  // Default to image size
    size_t low              = 0;
    size_t high             = sortedExportRVAs.size();
    while(low < high)  // simple binary search to find next highest RVA
    {
        size_t mid = low + (high - low) / 2;
        if(sortedExportRVAs[mid] <= rva)
        {
            low = mid + 1;
        }
        else
        {
            high = mid;
        }
    }

    if(low < sortedExportRVAs.size())
    {
        nextHighestRVA = sortedExportRVAs[low];
    }

    return nextHighestRVA - rva;
}

/**
 * @brief Validates that a given RVA range is within an image's bounds.
 *
 * @param rva The starting RVA.
 * @param size The size of the range.
 * @param imageSize The total size of the image.
 * @return true If the range is valid.
 * @return false Otherwise.
 */
inline bool isValidRvaRange(uint32_t rva, uint32_t size, uint32_t imageSize) noexcept
{
    return rva < imageSize && size <= (imageSize - rva);
}

/**
 * @brief Validates export directory table ranges.
 *
 * @param tableRVA The starting RVA of the table.
 * @param count The number of elements in the table.
 * @param elementSize The size of each element in the table.
 * @param imageSize The total size of the image.
 * @return true If the range is valid.
 * @return false Otherwise.
 */
bool isValidRvaTableRange(uint32_t tableRVA,
                          uint32_t count,
                          uint32_t elementSize,
                          uint32_t imageSize) noexcept
{
    const uint64_t totalSize = static_cast<uint64_t>(count) * elementSize;
    if(totalSize > UINT32_MAX)  // attempted overflow of DWORD
    {
        return false;
    }

    return isValidRvaRange(tableRVA, static_cast<uint32_t>(totalSize), imageSize);
}

bool isValidCStringRva(uint32_t rva, const uint8_t* base, uint32_t imageSize) noexcept
{
    if(rva >= imageSize)
    {
        return false;
    }

    const char* str     = reinterpret_cast<const char*>(base + rva);
    const size_t maxLen = imageSize - rva;
    return std::memchr(str, '\0', maxLen) != nullptr;
}
}  // namespace

}  // namespace ModuleParser
}  // namespace Crawlr
