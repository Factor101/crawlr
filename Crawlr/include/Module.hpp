#pragma once

#include "./detail/NativeDefs.hpp"
#include "Export.hpp"
#include "Syscall.hpp"
#include <map>
#include <string>
#include <vector>

namespace Crawlr
{
namespace ModuleParser
{
struct ModuleParseResult;  // forward declaration
}

using ExportMap  = std::map<std::string, Crawlr::Export>;
using SyscallMap = std::map<std::string, Crawlr::Syscall>;

class Module
{
 public:
    typedef struct MemoryInfo
    {
        const void* baseAddress;
        const IMAGE_EXPORT_DIRECTORY* exportDirectory;
        uint32_t imageSize;
        uint32_t exportDirRVA;
        uint32_t exportDirSize;
    };

 private:
    const wchar_t* moduleName;
    MemoryInfo memoryInfo;
    ExportMap exports;
    SyscallMap syscalls;


 public:
    Module(const wchar_t* moduleName) : moduleName(moduleName), exports(), syscalls() { }

    [[nodiscard]] ModuleParser::ModuleParseResult load() noexcept;

    template<typename T>  // pass either Export or Syscall, only place into syscall if T is Syscall
        requires std::is_base_of_v<Crawlr::Export, T>
    [[nodiscard]] T& addExport(std::string expName, const T& exp) noexcept;

    [[nodiscard]] inline const wchar_t* getModuleName() const noexcept { return this->moduleName; }
    [[nodiscard]] inline ExportMap& getExports() noexcept { return this->exports; }
    [[nodiscard]] inline SyscallMap& getSyscalls() noexcept { return this->syscalls; }
    [[nodiscard]] inline MemoryInfo getMemoryInfo() const noexcept { return this->memoryInfo; }

    inline bool removeExport(const std::string& expName) noexcept
    {
        return this->exports.erase(expName) > 0;
    }

    inline bool clearExports() noexcept
    {
        if(this->exports.empty())
        {
            return false;
        }

        this->exports.clear();
        return true;
    }
};
}  // namespace Crawlr
