#include "../include/Module.hpp"
#include "../include/ModuleParser.hpp"

namespace Crawlr
{
std::expected<Module::MemoryInfo, std::string> Module::load() noexcept
{
    auto res = ModuleParser::parseModuleMemoryInfo(this->moduleName);
    if(!res)
    {
        return std::unexpected(res.error());
    }

    this->memoryInfo = *res;
    return this->memoryInfo;
}

std::expected<void, std::string> Module::parseExports(
    const std::vector<std::string>& exportNames) noexcept
{
    return ModuleParser::parseExports(*this, exportNames);
}

std::expected<void, std::string> Module::parseExports(
    std::function<bool(const char* exportName)> nameFilter) noexcept
{
    return ModuleParser::parseExports(*this, nameFilter);
}
    Export& Module::addExport(std::string expName, const Export& exp) noexcept
{
    auto result = this->exports.emplace(expName, exp);
    return result.first->second;
}

Syscall& Module::addSyscall(std::string expName, const Syscall& sc) noexcept
{
    auto result = this->syscalls.emplace(expName, sc);
    return result.first->second;
}
}  // namespace Crawlr
