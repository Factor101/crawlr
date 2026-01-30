#pragma once

#include "Signature.hpp"

namespace Crawlr
{
namespace HookAnalysis
{
constexpr std::vector<Signature> DEFAULT_HOOK_SIGNATURES;
consteval void buildDefaultHookSignatures();

}  // namespace HookAnalysis
}  // namespace Crawlr
