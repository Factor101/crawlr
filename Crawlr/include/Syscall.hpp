#pragma once
#include "Export.hpp"

namespace Crawlr
{
class Syscall : public Export
{
 private:
    DWORD ssn;

 public:
    Syscall() = default;
    explicit Syscall(void* base) : Export(base) { }
    Syscall(void* base, DWORD ssn) : Export(base), ssn(ssn) { }
};
}  // namespace Crawlr
