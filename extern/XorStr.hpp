#pragma once
#ifndef _XORSTR_HPP
#define _XORSTR_HPP

#include <cstddef>

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
class XorStr
{
 private:
 public:
};


}  // namespace

XORSTR_FORCEINLINE constexpr XorStr operator""_xor(const char* str, std::size_t size) { }

}  // namespace XorStr
}  // namespace Crawlr

#endif
