#pragma once
#include "Signature.hpp"
#include <unordered_map>

namespace Crawlr
{
namespace HookAnalysis
{
enum class HookType
{
    EDR_BITDEFENDER,
    EDR_MALWAREBYTES,
    GENERIC_JMP
};

using SignatureMap = std::unordered_map<HookType, Signature>;
void buildDefaultSignatureList();


}  // namespace HookAnalysis
}  // namespace Crawlr
