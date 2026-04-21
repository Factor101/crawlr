#pragma once
#include <unordered_map>
#include "Signature.hpp"

namespace Crawlr
{
namespace HookAnalysis
{
enum class HookType
{
    EDR_BITDEFENDER,
    GENERIC_JMP
};

using SignatureMap = std::unordered_map<HookType, Signature>;

SignatureMap knownHooks;

void buildDefaultSignatureList();

}  // namespace HookAnalysis
}  // namespace Crawlr
