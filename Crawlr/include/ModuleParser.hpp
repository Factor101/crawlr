#pragma once
#include "Export.hpp"
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace Crawlr
{
struct ParseResult
{
    bool success;
    std::string error;
    std::map<std::string, Export> exports;
};

class ModuleParser
{
 public:
    static ParseResult parseExports(const wchar_t* moduleName, const std::vector<std::string>& targetNames = {});

 private:
    static std::optional<void*> getModuleBase(const wchar_t* moduleName);
    static ParseResult parseExportDirectory(void* moduleBase, const std::vector<std::string>& targetNames = {});
};
}  // namespace Crawlr
