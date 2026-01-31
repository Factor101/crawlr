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


template<typename T>  // pass either Export or Syscall, only place into syscall if T is Syscall
    requires std::is_base_of_v<Crawlr::Export, T>
T& Module::addExport(std::string expName, const T& exp) noexcept
{
    auto result = this->exports.emplace(expName, exp);
    if constexpr(std::is_same_v<T, Crawlr::Syscall>)
    {
        this->syscalls.emplace(expName, &result.first->second);
    }

    return result.first->second;
}
}  // namespace Crawlr
