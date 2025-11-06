#pragma once

#include "./detail/NativeDefs.hpp"
#include "Export.hpp"
#include "Syscall.hpp"
#include "ModuleParser.hpp"
#include <map>
#include <string>
#include <vector>

namespace Crawlr
{
using ExportMap  = std::map<std::string, Crawlr::Export>;
using SyscallMap = std::map<std::string, Crawlr::Syscall>;

class Module
{
 public:
    typedef struct MemoryInfo
    {
        uint8_t* baseAddress;
        IMAGE_EXPORT_DIRECTORY* exportDirectory;
    };

 private:
    const wchar_t* moduleName;
    MemoryInfo memoryInfo;
    ExportMap exports;
    SyscallMap syscalls;


 public:
    Module(const wchar_t* moduleName) : moduleName(moduleName), exports(), syscalls() { }

    ModuleParser::Result load() noexcept;

    template<typename T> T& addExport(const std::string& expName, const T& exp) noexcept;

    inline const wchar_t* getModuleName() const noexcept { return this->moduleName; }
    inline ExportMap& getExports() noexcept { return this->exports; }
    inline SyscallMap& getSyscalls() noexcept { return this->syscalls; }
    inline MemoryInfo getMemoryInfo() const noexcept { return this-> memoryInfo; }

    inline bool removeExport(const std::string& expName) noexcept { return this->exports.erase(expName) > 0; }
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
