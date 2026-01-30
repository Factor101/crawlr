#pragma once

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace Crawlr
{
using PatternByte = std::optional<uint8_t>;
using Pattern     = std::vector<PatternByte>;

class Signature
{
 private:
    Pattern pattern;
    static Pattern parseHexString(std::string_view hexPattern);
    static uint8_t byteFromNibbles(const char high, const char low);

 public:
    static constexpr PatternByte WILDCARD = std::nullopt;

    Signature() = default;

    // Constructor for all string-like types.
    // Valid formats: "FF 0A ?? BB 05", "FF0A??BB05"
    explicit Signature(std::string_view hexPattern) : pattern(parseHexString(hexPattern)) { }

    // Constructor initializer list of PatternByte.
    // e.g. Signature{ 0xFF, 0x0A, Signature::WILDCARD, 0xBB, 0x05 }
    Signature(std::initializer_list<PatternByte> pattern) : pattern(pattern) { }

    // Constructor from Pattern.
    explicit Signature(const Pattern& pattern) : pattern(pattern) { }

    // Factory methods for raw byte arrays.
    static Signature fromBytes(const uint8_t* bytes, size_t size);
    static Signature fromBytes(std::span<const uint8_t> bytes);

    std::vector<size_t> matchAll(const uint8_t* pData, size_t dataSize) const noexcept;
    size_t matchFirst(const uint8_t* pData, size_t dataSize) const noexcept;
};
}  // namespace Crawlr
