#pragma once
#include "Export.hpp"
#include <array>
#include <type_traits>

// clang-format off
extern "C" __attribute__((naked))
uintptr_t invokeSyscall(uint32_t ssn, void* pSyscall,
    uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
    uintptr_t a5, uintptr_t a6, uintptr_t a7, uintptr_t a8);

namespace Crawlr
{
class Syscall : public Export
{
 private:
    uint32_t ssn;
    void* pSyscallOpcode;

 public:
    Syscall(void* base,
            const uint32_t rva,
            const uint32_t size,
            uint32_t ssn         = 0,
            void* pSyscallOpcode = nullptr)
        : Export(base, rva, size), ssn(ssn), pSyscallOpcode(pSyscallOpcode)
    { }

    template<typename Return = uintptr_t, typename... Args>
    Return invoke(Args... args) const noexcept
    {
        static_assert(sizeof...(Args) <= 8,
                      "Syscall must be invoked with <= 8 arguments");
        auto toUintptr = []<typename T>(T arg) -> uintptr_t {
            if constexpr(std::is_pointer_v<T>)
            {
                return reinterpret_cast<uintptr_t>(arg);
            }
            else
            {
                return static_cast<uintptr_t>(arg);
            }
        };

        std::array<uintptr_t, 8> arr{};
        size_t i = 0;
        ((arr[i++] = toUintptr(args)), ...);  // pack args into array

        uintptr_t invokeResult = invokeSyscall(
            this->ssn, this->pSyscallOpcode,
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7]);

        return static_cast<Return>(invokeResult);
    }
};
}  // namespace Crawlr
// clang-format on
