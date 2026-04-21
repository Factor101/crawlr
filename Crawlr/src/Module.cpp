#include "../include/Module.hpp"
#include "../include/ModuleParser.hpp"

namespace Crawlr
{
ModuleParser::ModuleParseResult Module::load() noexcept
{
    this->memoryInfo = ModuleParser::parseModuleMemoryInfo(this->moduleName);
    if(!this->memoryInfo.baseAddress || !this->memoryInfo.exportDirectory)
    {
        return { false, "Failed to parse module memory.", this->memoryInfo };
    }

    return { true, "", this->memoryInfo };
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
