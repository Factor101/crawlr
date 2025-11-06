#pragma once

namespace Crawlr
{
class Export
{
 protected:
    void* baseAddress;
    ULONG size;

 public:
    Export() = default;
    explicit Export(void* base) : baseAddress(base) { }
    Export(void* base, ULONG sz) : baseAddress(base), size(sz) { }

    [[nodiscard]] void* getBaseAddress() const noexcept { return baseAddress; }
    [[nodiscard]] ULONG getSize() const noexcept { return size; }
};
}  // namespace Crawlr
