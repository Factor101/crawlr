#include "../include/ModuleExports.hpp"
#include "../include/ModuleParser.hpp"
#include <format>

namespace Crawlr
{
Module& ModuleExports::addModule(const wchar_t* moduleName)
{
    auto result = this->modules.emplace(moduleName, Crawlr::Module(moduleName));
    return result.first->second;
}


////////////////////
// below functions will be refactored to return a different result type later.
// trying to avoid unnecessary coupling.
////////////////////
// ModuleParser::ExportsParseResult ModuleExports::mapExports(
//     const std::wstring moduleName,
//     const std::vector<std::string>& exportNames = {})
// {
//     const auto mod = this->modules.find(moduleName);
//     if(mod == this->modules.end())
//     {
//         return { false,
//                  std::format("The module '{}' was not found in the export table", moduleName) };
//     }

//     return this->mapExports(mod->second, exportNames);
// }

// ModuleParser::ExportsParseResult ModuleExports::mapExports(
//     Module& module,
//     const std::vector<std::string>& exportNames = {})
// {
//     if(!this->modules.contains(module.getModuleName()))
//     {
//         this->modules.insert({ module.getModuleName(), module });
//     }

//     return ModuleParser::parseExports(module, exportNames);
// }

}  // namespace Crawlr
