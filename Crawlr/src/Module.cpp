#include "../include/ModuleParser.hpp"

namespace Crawlr
{

ModuleParser::Result Module::load() noexcept
{
    this->memoryInfo = ModuleParser::parseModuleMemory(this->moduleName);
    if(!this->memoryInfo.baseAddress || !this->memoryInfo.exportDirectory)
    {
        return { false, "Failed to parse module memory.", {}, this->exports, this->syscalls };
    }

    auto result = ModuleParser::parseExportDirectory(this->memoryInfo.baseAddress);
    if(!result.success)
    {
        return { false, result.error, {}, this->exports, this->syscalls };
    }

    return { true, "", this->memoryInfo, this->exports, this->syscalls };
}


template<typename T>  // pass either Export or Syscall, only place into syscall if T is Syscall
T& Module::addExport(const std::string& expName, const T& exp) noexcept
{
    static_assert(std::is_base_of_v<Crawlr::Export, T>, "T must be derived from Crawlr::Export");

    auto result = this->exports.emplace(expName, exp);
    if constexpr(std::is_same_v<T, Crawlr::Syscall>)
    {
        this->syscalls.emplace(expName, &result.first->second);
    }

    return result.first->second;
}
}  // namespace Crawlr

