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

    std::map<const wchar_t*, Crawlr::Module> modules;

 public:
    Crawlr::Module& addModule(const wchar_t* moduleName);
    bool mapExports(const std::vector<const char*>& exportNames);
};
}  // namespace Crawlr
