#pragma once

#include "./detail/NativeDefs.hpp"
#include "Export.hpp"
#include "Syscall.hpp"
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace Crawlr
{
using ExportMap  = std::map<std::string, Crawlr::Export>;
using SyscallMap = std::map<std::string, Crawlr::Syscall>;

class Module
{
 public:
    struct MemoryInfo
    {
        const void* baseAddress;
        const IMAGE_EXPORT_DIRECTORY* exportDirectory;
        uint32_t imageSize;
        uint32_t exportDirRva;
        uint32_t exportDirSize;
    };

 private:
    std::wstring moduleName;
    MemoryInfo memoryInfo;
    ExportMap exports;
    SyscallMap syscalls;

 public:
    Module(std::wstring moduleName) : moduleName(moduleName), exports(), syscalls() { }

    [[nodiscard]] std::expected<MemoryInfo, std::string> load() noexcept;

    std::expected<void, std::string> parseExports(
        const std::vector<std::string>& exportNames) noexcept;
    std::expected<void, std::string> parseExports(
        std::function<bool(const char* exportName)> nameFilter) noexcept;

    Export& addExport(std::string expName, const Export& exp) noexcept;
    Syscall& addSyscall(std::string expName, const Syscall& sc) noexcept;

    [[nodiscard]] inline ExportMap& getExports() noexcept { return this->exports; }  //TODO: need to protect against uninit
    [[nodiscard]] inline SyscallMap& getSyscalls() noexcept { return this->syscalls; }

    [[nodiscard]] inline Export* getExport(const std::string& exportName) noexcept
    {
        auto it = this->exports.find(exportName);
        return it != this->exports.end() ? &it->second : nullptr;
    }

    [[nodiscard]] inline Syscall* getSyscall(const std::string& syscallName) noexcept
    {
        auto it = this->syscalls.find(syscallName);
        return it != this->syscalls.end() ? &it->second : nullptr;
    }

    [[nodiscard]] inline MemoryInfo getMemoryInfo() const noexcept
    {
        return this->memoryInfo;
    }

    [[nodiscard]] inline std::wstring getModuleName() const noexcept
    {
        return this->moduleName;
    }

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
