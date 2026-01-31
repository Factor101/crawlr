#include "../include/Signature.hpp"
#include <algorithm>

namespace Crawlr
{

Signature Signature::fromBytes(const uint8_t* bytes, size_t size)
{
    Pattern p;
    p.reserve(size);
    for(size_t i = 0; i < size; ++i)
    {
        p.push_back(bytes[i]);
    }

    return Signature{ p };
}

Signature Signature::fromBytes(std::span<const uint8_t> bytes)
{
    return fromBytes(bytes.data(), bytes.size());
}

uint8_t Signature::byteFromNibbles(const char high, const char low)
{
    // Converts a nibble character to its byte value.
    const auto nibbleToValue = [](const char c) -> uint8_t {
        if(c >= '0' && c <= '9')
        {
            return static_cast<uint8_t>(c - '0');
        }
        else if(c >= 'A' && c <= 'F')
        {
            return static_cast<uint8_t>(c - 'A' + 10);
        }
        else if(c >= 'a' && c <= 'f')
        {
            return static_cast<uint8_t>(c - 'a' + 10);
        }
        else
        {
            throw std::invalid_argument("Invalid hex digit in signature pattern");
        }
    };

    // High and low nibbles are converted a byte first before combining.
    // e.g.  0xF5 = 1111'0101
    // high = 0xF = 0000'1111
    // low  = 0x5 = 0000'0101
    // (0xF << 4) | 0x5 = 1111'0000 | 0000'0101 = 1111'0101
    return (nibbleToValue(high) << 4) | nibbleToValue(low);
}

Pattern Signature::parseHexString(std::string_view pattern)
{
    std::vector<PatternByte> parsedPattern;
    parsedPattern.reserve(pattern.size() / 2);

    size_t i = 0;
    while(i < pattern.size())
    {
        char c = pattern[i];
        if(c == ' ')
        {
            ++i;
            continue;
        }

        if(c == '?')
        {
            // Consume '?' char as wildcard.
            parsedPattern.push_back(Signature::WILDCARD);
            ++i;

            // Void additional '?' char if present.
            if(i < pattern.size() && pattern[i] == '?')
            {
                ++i;
            }

            continue;
        }

        if(i + 1 >= pattern.size())
        {
            throw std::invalid_argument("Invalid hex byte found in signature pattern");
        }

        parsedPattern.push_back(byteFromNibbles(pattern[i], pattern[i + 1]));
        i += 2;
    }

    return parsedPattern;
}

std::vector<size_t> Signature::matchAll(const uint8_t* pData, size_t dataSize) const noexcept
{
    std::vector<size_t> matches;

    if(this->isEmpty() || dataSize < this->size())
    {
        return matches;
    }

    // Match all occurences and store match indices.
    size_t offset = 0;
    while(offset < dataSize - this->size() + 1)
    {
        size_t relativeMatch = this->matchFirst(pData + offset, dataSize - offset);
        if(relativeMatch == static_cast<size_t>(-1))
        {
            break;
        }

        // We are shifting the start of the search window by offset, so we must
        // add offset back to the relative match idx to get the absolute idx.
        size_t absoluteMatch = offset + relativeMatch;
        matches.push_back(absoluteMatch);
        offset = absoluteMatch + 1;
    }

    return matches;
}

size_t Signature::matchFirst(const uint8_t* pData, size_t dataSize) const noexcept
{
    if(this->isEmpty() || dataSize < this->size())
    {
        return Signature::npos;
    }

    // Search lambda to compare bytes with pattern, accounting for wildcards.
    // A wildcard byte == Signature::WILDCARD == std::nullopt.
    const auto byteMatchesPattern = [](uint8_t byte, PatternByte patternByte) -> bool {
        return !patternByte.has_value() || byte == patternByte.value();
    };

    auto it = std::search(pData,
                          pData + dataSize,
                          this->pattern.begin(),
                          this->pattern.end(),
                          byteMatchesPattern);

    return (it != (pData + dataSize)) ? static_cast<size_t>(std::distance(pData, it))
                                      : Signature::npos;
}


bool Signature::matches(const uint8_t* pData, size_t dataSize) const noexcept
{
    return this->matchFirst(pData, dataSize) != Signature::npos;
}

bool Signature::matchesAt(const uint8_t* pData, size_t dataSize, size_t offset) const noexcept
{
    if(this->isEmpty() || dataSize < this->size() + offset)
    {
        return false;
    }

    return this->matchFirst(pData + offset, dataSize - offset) != Signature::npos;
}

}  // namespace Crawlr
