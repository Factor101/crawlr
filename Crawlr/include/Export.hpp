#pragma once
#include <cstdint>

namespace Crawlr
{
class Export
{
 protected:
    void* baseAddress;
    uint32_t rva;
    uint32_t size;

 public:
    Export(void* base, const uint32_t rva, const uint32_t size)
        : baseAddress(base), rva(rva), size(size)
    { }

    [[nodiscard]] void* getBaseAddress() const noexcept { return baseAddress; }
    [[nodiscard]] uint32_t getSize() const noexcept { return size; }
};
}  // namespace Crawlr
