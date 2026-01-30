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
    std::map<std::wstring, Crawlr::Module> modules;

 public:
    ModuleExports() : modules{} { }

    Module& addModule(const wchar_t* moduleName);
    bool mapExports(const std::vector<std::string>& exportNames); // TOOD: change exportNames type to span<const stview>
};
}  // namespace Crawlr
