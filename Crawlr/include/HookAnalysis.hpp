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

NtAllocateVirtualMemory(



  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN ULONG                ZeroBits,
  IN OUT PULONG           RegionSize,
  IN ULONG                AllocationType,
  IN ULONG                Protect );



mov     r10, rcx
mov     eax, 17h
test    byte ptr [7FFE0308h], 1
jne     ntdll!NtQueryValueKey+0x15 (7ffb42581ed5)
syscall
ret
