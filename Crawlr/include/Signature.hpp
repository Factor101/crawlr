#pragma once

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace Crawlr
{
using PatternByte = std::optional<uint8_t>;
using Pattern     = std::vector<PatternByte>;

// I.e. NOT string literals.
template<typename T>
concept RuntimeString = std::is_same_v<std::decay_t<T>, std::string>
                     || std::is_same_v<std::decay_t<T>, std::string_view>;

class ValidatedPattern
{
 private:
    std::string_view pattern;

    static consteval bool isValidChar(char c)  // clang-format off
    {
        return c == '?' || c == ' '
            || (c >= '0' && c <= '9')
            || (c >= 'A' && c <= 'F')
            || (c >= 'a' && c <= 'f');  // clang-format on
    }

    static consteval std::string_view validate(std::string_view pattern)
    {
        for(size_t i = 0; i < pattern.size(); ++i)
        {
            if(!isValidChar(pattern[i]))
            {
                throw std::invalid_argument("Invalid character found in hex signature pattern");
            }
        }

        return pattern;
    }

 public:
    template<size_t N>
    consteval ValidatedPattern(const char (&pattern)[N])
        : pattern(validate(std::string_view(pattern, N - 1)))
    { }

    constexpr std::string_view get() const noexcept { return pattern; }
    constexpr operator std::string_view() const noexcept { return pattern; }
};

class Signature
{
 private:
    Pattern pattern;
    static Pattern parseHexString(std::string_view hexPattern);
    static uint8_t byteFromNibbles(const char high, const char low);

 public:
    static constexpr PatternByte WILDCARD = std::nullopt;
    static constexpr size_t npos          = static_cast<size_t>(-1);

    Signature() = default;

    // Compile-time validated for string literals.
    template<size_t N>
    Signature(const char (&pattern)[N]) : pattern(parseHexString(ValidatedPattern(pattern).get()))
    { }

    // Constructor for runtime strings.
    template<RuntimeString T>
    explicit Signature(T&& hexPattern) : pattern(parseHexString(std::forward<T>(hexPattern)))
    { }

    // Constructor initializer list of PatternByte.
    // e.g. Signature{ 0xFF, 0x0A, Signature::WILDCARD, 0xBB, 0x05 }
    Signature(std::initializer_list<PatternByte> pattern) : pattern(pattern) { }

    // Constructor from Pattern.
    explicit Signature(const Pattern& pattern) : pattern(pattern) { }

    // Factory methods for raw byte arrays.
    [[nodiscard]] static Signature fromBytes(const uint8_t* bytes, size_t size);
    [[nodiscard]] static Signature fromBytes(std::span<const uint8_t> bytes);

    // Matchers
    [[nodiscard]] size_t matchFirst(const uint8_t* pData, size_t dataSize) const noexcept;
    [[nodiscard]] std::vector<size_t> matchAll(const uint8_t* pData,
                                               size_t dataSize) const noexcept;

    // Getters
    [[nodiscard]] const Pattern& getPattern() const noexcept { return pattern; }
    [[nodiscard]] size_t size() const noexcept { return pattern.size(); }
    [[nodiscard]] bool empty() const noexcept { return pattern.empty(); }
};
}  // namespace Crawlr
