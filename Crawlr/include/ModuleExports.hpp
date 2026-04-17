#pragma once
#include "Export.hpp"
#include "Module.hpp"
#include <map>
#include <string>
#include <vector>

namespace Crawlr
{
class ModuleExports
{
 private:
    std::map<std::wstring, Module> modules;

 public:
    ModuleExports() : modules{} { }

    Module& addModule(const wchar_t* moduleName);
};
}  // namespace Crawlr
