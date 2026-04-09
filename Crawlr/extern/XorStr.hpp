#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

#ifdef _MSC_VER
#define XORSTR_FORCEINLINE __forceinline
#else
#define XORSTR_FORCEINLINE __attribute__((always_inline)) inline
#endif

namespace Crawlr
{
namespace XorStr
{
namespace
{
XORSTR_FORCEINLINE consteval uint64_t key64()
{
    constexpr uint64_t FNV1A_OFFSET = 0xcbf29ce484222325ull;
    constexpr uint64_t FNV1A_PRIME  = 0x00000100000001b3ull;
    uint64_t hash                   = FNV1A_OFFSET;

    // hh:mm:ss
    for(const uint8_t c : __TIME__)
    {
        if(c == ':')
        {
            continue;
        }

        hash ^= c;
        hash *= FNV1A_PRIME;
    }

    return hash;
}

XORSTR_FORCEINLINE consteval uint64_t encryptBlock(const char* str,
                                                   size_t len,
                                                   size_t offset,
                                                   uint64_t key) noexcept
{
    uint64_t encrypted = 0;
    for(size_t i = 0; i < 8 && (offset + i) < len; ++i)
    {
        // Pack chars into buffer; little-endian
        encrypted |= uint64_t{ static_cast<uint8_t>(str[offset + i]) } << (i * 8);
    }

    return encrypted ^ key;
}


template<size_t N>
class XorStr
{
 private:
    static constexpr size_t BUFFER_CHUNKS = (N / 8) + (N % 8 != 0);
    static constexpr size_t BUFFER_SIZE   = BUFFER_CHUNKS * 8;
    static constexpr uint64_t KEY         = key64();
    uint64_t buffer[BUFFER_CHUNKS]{};  // needs to be aligned if going SIMD route

    template<size_t... I>
    XORSTR_FORCEINLINE consteval XorStr(const char (&str)[N], std::index_sequence<I...>) noexcept
        : buffer{ encryptBlock(str, N, I * 8, KEY)... }
    { }

 public:
    XORSTR_FORCEINLINE consteval explicit XorStr(const char (&s)[N]) noexcept
        : XorStr(s, std::make_index_sequence<BUFFER_CHUNKS>{})
    { }

    [[nodiscard]] XORSTR_FORCEINLINE std::array<char, N> decrypt() const noexcept
    {
        std::array<char, N> result{};
        // needs to be volatile to prevent compiler optimization
        const volatile uint64_t* src = buffer;

        for(size_t i = 0; i < BUFFER_CHUNKS; ++i)
        {
            const uint64_t chunk = src[i] ^ KEY;
            for(size_t j = 0; j < 8 && (i * 8 + j) < N; ++j)
            {
                // Unpack chars from buffer (stored in little-endian format)
                result[i * 8 + j] = static_cast<char>((chunk >> (j * 8)) & 0xFF);
            }
        }

        return result;
    }
};

#define XORSTR(str)                                                    \
    ([]() noexcept -> ::std::array<char, sizeof(str)> {                \
        constexpr ::Crawlr::XorStr::XorStr<sizeof(str)> xorStr{ str }; \
        return xorStr.decrypt();                                       \
    }())
}  // namespace
}  // namespace XorStr
}  // namespace Crawlr
