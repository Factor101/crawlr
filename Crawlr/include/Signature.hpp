#pragma once

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

namespace Crawlr
{

template<typename T>
concept StringLike = std::is_same_v<std::string_view, std::remove_cvref_t<T>>
                  || (std::is_same_v<char*, std::remove_reference_t<T>>
                      || std::is_same_v<const char*, std::remove_reference_t<T>>)
                  || (std::is_array_v<std::remove_reference_t<T>>)
                  || (std::is_pointer_v<std::remove_reference_t<T>>
                      && std::is_integral_v<std::remove_pointer<std::remove_reference_t<T>>>
                      && sizeof(std::remove_pointer_t<std::remove_reference_t<T>>) == 1);
class Signature
{
 private:
    std::vector<uint8_t> pattern;

 public:
    Signature() = default;

    template<StringLike T>
    constexpr Signature(const T& pattern) noexcept;

    std::vector<size_t> matchAll(const uint8_t* pData, size_t dataSize) const noexcept;
    size_t matchFirst(const uint8_t* pData, size_t dataSize) const noexcept;
};
}  // namespace Crawlr
