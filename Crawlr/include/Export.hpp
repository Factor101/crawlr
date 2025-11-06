#pragma once

namespace Crawlr
{
class Export
{
 protected:
    void* baseAddress;

 public:
    Export() = default;
    explicit Export(void* base) : baseAddress(base) { }
};
}  // namespace Crawlr
