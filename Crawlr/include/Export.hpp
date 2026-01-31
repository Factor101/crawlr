#pragma once
#include <cstdint>

namespace Crawlr
{
class Export
{
 protected:
    const void* baseAddress;
    const uint32_t rva;
    const uint32_t size;

 public:
    Export() = default;
    explicit Export(const void* base) : baseAddress(base) { }
    Export(const void* base, const uint32_t rva, const uint32_t size)
        : baseAddress(base), rva(rva), size(size)
    { }

    [[nodiscard]] const void* getBaseAddress() const noexcept { return baseAddress; }
    [[nodiscard]] uint32_t getSize() const noexcept { return size; }
};
}  // namespace Crawlr
