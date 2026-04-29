#pragma once
#include "include/Module.hpp"
#include <expected>

namespace Crawlr
{
std::expected<Module, std::string> loadModule(
    const std::wstring& moduleName,
    const std::vector<std::string>& targetNames = {});

bool populateModule(Module& module, const std::vector<std::string>& targetNames = {});
}  // namespace Crawlr
