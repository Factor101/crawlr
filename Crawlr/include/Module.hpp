#pragma once
#include "Export.hpp"
#include <map>
#include <string>
#include <vector>

namespace Crawlr
{
using ExportMap  = std::map<const std::string, Crawlr::Export>;
using SyscallMap = std::map<const std::string, Crawlr::Export*>;

class Module
{
 private:
    ExportMap exports;
    SyscallMap syscalls;  // pointers to syscall-type members of exports

 public:
    Module(const wchar_t* moduleName);
    ExportMap& getExports() { return this->exports; }
    SyscallMap& getSyscalls() { return this->syscalls; }
};
}  // namespace Crawlr
