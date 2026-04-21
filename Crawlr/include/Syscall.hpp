#pragma once
#include "Export.hpp"
#include <array>

extern "C" __attribute__((naked)) uintptr_t invokeSyscall(uint32_t ssn,
                                                          void* pSyscall,
                                                          uintptr_t a1,
                                                          uintptr_t a2,
                                                          uintptr_t a3,
                                                          uintptr_t a4,
                                                          uintptr_t a5,
                                                          uintptr_t a6,
                                                          uintptr_t a7,
                                                          uintptr_t a8);

namespace Crawlr
{
class Syscall : public Export
{
 private:
    uint32_t ssn;
    void* pSyscallOpcode;

 public:
    Syscall(void* base, const uint32_t rva, const uint32_t size, uint32_t ssn = 0)
        : Export(base, rva, size), ssn(ssn)
    { }

    template<typename Return = uintptr_t, typename... Args>
    Return invoke(Args... args) const noexcept
    {
        static_assert(sizeof...(Args) <= 8, "Syscall must be invoked with <= 8 arguments");

        std::array<uintptr_t, 8> args{};
        size_t i = 0;
        ((args[i++] = static_cast<uintptr_t>(args)), ...);  // pack args into array

        uintptr_t invokeResult= invokeSyscall(this->ssn,
                                               this->pSyscallOpcode,
                                               a[0],a[1],
                                               a[2],
                                               a[3],
                                               a[4],
                                               a[5],
                                               a[6],
                                               a[7]);

        return static_cast<Return>(invokeResult);
    }
};
}  // namespace Crawlr
