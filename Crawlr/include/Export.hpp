#pragma once
#include <cstdint>

namespace Crawlr
{
class Export
{
 protected:
    void* baseAddress;
    const uint32_t rva;
    const uint32_t size;

 public:
    Export() = default;
    explicit Export(void* base) : baseAddress(base) { }
    Export(void* base, const uint32_t rva, const uint32_t size)
        : baseAddress(base), rva(rva), size(size)
    { }

    [[nodiscard]] void* getBaseAddress() const noexcept { return baseAddress; }
    [[nodiscard]] uint32_t getSize() const noexcept { return size; }
};
}  // namespace Crawlr
