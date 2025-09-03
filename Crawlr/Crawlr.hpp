#pragma once
#include "include/Export.hpp"
#include "include/Module.hpp"
#include "include/ModuleExports.hpp"
#include <expected>

namespace Crawlr
{
std::expected<Module, std::string> loadModule(const wchar_t* moduleName,
                                              const std::vector<std::string>& targetNames = {});
bool populateModule(Module& module, const std::vector<std::string>& targetNames = {});
}  // namespace Crawlr
