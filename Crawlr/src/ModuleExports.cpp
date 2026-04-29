#include "../include/ModuleExports.hpp"
#include "../include/ModuleParser.hpp"
#include <format>

namespace Crawlr
{
Module& ModuleExports::addModule(const std::wstring& moduleName)
{
    auto result = this->modules.emplace(moduleName, Crawlr::Module(moduleName));
    return result.first->second;
}
}  // namespace Crawlr
