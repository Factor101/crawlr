#pragma once
#ifndef _XORSTR_HPP
#define _XORSTR_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

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

union Hash32
{
    uint32_t hash;
    uint8_t blocks[4];
};

XORSTR_FORCEINLINE consteval Hash32 key32()
{
    constexpr uint32_t FNV1A_OFFSET = 2'166'136'261ull;
    constexpr uint32_t FNV1A_PRIME  = 16'777'619ull;
    Hash32 hash                     = { FNV1A_OFFSET };

    // hh:mm:ss
    for(const uint8_t c : __TIME__)
    {
        if(c == ':')
        {
            continue;
        }

        hash.hash ^= c;
        hash.hash *= FNV1A_PRIME;
    }

    return hash;
}

class XorStr
{
 private:
    static constexpr Hash32 key = key32();
    const std::string_view str;

    static consteval void encrypt(std::string_view& sv)
    {

    }

 public:
    XORSTR_FORCEINLINE consteval explicit XorStr(const std::string_view& sv)
    {
    }
};


}  // namespace

XORSTR_FORCEINLINE constexpr XorStr operator""_xor(const char* str, std::size_t size) { }

}  // namespace XorStr
}  // namespace Crawlr

#endif
