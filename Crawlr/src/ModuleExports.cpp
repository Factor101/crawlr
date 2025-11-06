#include "../include/Module.hpp"
#include "../include/ModuleExports.hpp"

namespace Crawlr
{
Crawlr::Module& ModuleExports::addModule(const wchar_t* moduleName)
{
    auto result = this->modules.emplace(moduleName, Crawlr::Module(moduleName));
    return result.first->second;
}
}  // namespace Crawlr
