#pragma once
#include "Export.hpp"
#include "Module.hpp"
#include "Syscall.hpp"
#include <expected>
#include <functional>
#include <string>
#include <vector>

namespace Crawlr
{
namespace ModuleParser
{
std::expected<Module::MemoryInfo, std::string> parseModuleMemoryInfo(
    const std::wstring& moduleName) noexcept;

std::expected<void, std::string> parseExports(
    Module& module,
    const std::vector<std::string>& exportNames = {}) noexcept;

std::expected<void, std::string> parseExports(
    Module& module,
    std::function<bool(const char* exportName)> nameFilter) noexcept;
}  // namespace ModuleParser
}  // namespace Crawlr
