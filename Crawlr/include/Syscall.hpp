#pragma once
#include "Export.hpp"

namespace Crawlr
{
class Syscall : public Export
{
 private:
    DWORD ssn;

 public:
    Syscall(void* base, const uint32_t rva, const uint32_t size, DWORD ssn = 0)
        : Export(base, rva, size), ssn(ssn)
    { }
};
}  // namespace Crawlr
