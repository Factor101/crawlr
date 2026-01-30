#include "../include/HookAnalysis.hpp"

namespace Crawlr
{
namespace HookAnalysis
{
void buildDefaultSignatureList()
{
    knownHooks = {
        { HookType::EDR_BITDEFENDER, Signature("E9 ?? ?? ?? ??") }
    };
}
}  // namespace HookAnalysis
}  // namespace Crawlr
