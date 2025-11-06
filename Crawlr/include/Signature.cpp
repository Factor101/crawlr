#include "../include/Signature.hpp"

namespace Crawlr
{
template<StringLike T>
constexpr Signature::Signature(const T& pattern) noexcept
{
    if constexpr(std::is_same_v<std::remove_cvref_t<T>, std::string_view>)
    {
        this->pattern.reserve(pattern.size());
        for(char c : pattern)
        {
            this->pattern.push_back(static_cast<uint8_t>(c));
        }
    }
    else if constexpr(std::is_array_v<std::remove_reference_t<T>>)
    {
        constexpr size_t length = sizeof(pattern) / sizeof(pattern[0]);
        this->pattern.reserve(length);
        for(size_t i = 0; i < length; ++i)
        {
            this->pattern.push_back(static_cast<uint8_t>(pattern[i]));
        }
    }
    else if constexpr(std::is_pointer_v<std::remove_reference_t<T>>)
    {
        // Assuming null-terminated C-string
        // TODO: Add bounds check or restrict concept from unknown lengths
        const char* ptr = pattern;
        while(*ptr != '\0')
        {
            this->pattern.push_back(static_cast<uint8_t>(*ptr));
            ++ptr;
        }
    }

    _DEBUG_PRINTF("[i] Signature pattern %c loaded: Constexpr hit?: %s\n",
                  typeid(T).name(),
                  (std::is_constant_evaluated() ? "true" : "false"));
}

std::vector<size_t> Signature::matchAll(const uint8_t* pData, size_t dataSize) const noexcept
{
    std::vector<size_t> matches;

    if(this->pattern.empty() || dataSize < this->pattern.size())
    {
        return matches;
    }

    const uint8_t* pDataEnd = pData + dataSize - this->pattern.size() + 1;

    size_t offset = 0;
    while((offset = this->matchFirst(pData + offset, pDataEnd - (pData + offset))) != -1)
    {
        matches.push_back(offset);
        offset += 1;
    }
}

size_t Signature::matchFirst(const uint8_t* pData, size_t dataSize) const noexcept
{
    auto it =
        std::search(pData,
                    pData + dataSize,
                    this->pattern.begin(),
                    this->pattern.end(),
                    [&](uint8_t dataByte, uint8_t patternByte) { return dataByte == patternByte; });
    return (it != (pData + dataSize)) ? std::distance(pData, it) : -1;
}

}  // namespace Crawlr
