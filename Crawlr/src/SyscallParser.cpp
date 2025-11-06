#include "../include/SyscallParser.hpp"
#include <type_traits>

namespace Crawlr
{
namespace SyscallParser
{
ScanResult scanExport(const Export& exp) noexcept
{

}

// able to pass in void* or Export-derived class
template<typename T>
DWORD* scanSyscallOpAddress(const T& exp) noexcept
{
	const void* base;
	if constexpr(std::is_same_v<T, void*>)
	{
		base = exp;
	}
	else
	{
		static_assert(std::is_base_of_v<Crawlr::Export, T>, "T must be derived from Crawlr::Export");
		base = exp.baseAddress;
	}
}

} // namespace ExportParser
} // namespace Crawlr


UINT_PTR Syscall::getSyscallAddress(PVOID pFunctionBase)
{
	for(int i = 0; i < 0x30; i++)
	{
		PBYTE pCurrentByte = (PBYTE)pFunctionBase + i;
		if(*pCurrentByte == 0x0F && *(pCurrentByte + 1) == 0x05)
		{
			return (UINT_PTR)pCurrentByte;
		}
	}

	return 0;
}

// _NODISCARD DWORD Syscall::searchSSN(PVOID pFunctionBase)
// {
// 	constexpr BYTE syscallSignature[] = {
// 		0x4c, 0x8b, 0xd1, // mov r10, rcx
// 		0xb8, // mov eax, ? ? ? ?
// 	};

// 	// bitdefender EDR inserts JMP
// 	constexpr BYTE JMP_INSTRUCTION = 0xE9;

// 	if(*(PBYTE)pFunctionBase == JMP_INSTRUCTION) {
// 		// function is hooked
// 	} else {
// 		// ssn must be pFunctionBase + 0x04
// 		return *(PBYTE)((PBYTE)pFunctionBase + 0x04);
// 	}
// }

// __forceinline _NODISCARD boolean Syscall::isHooked(PVOID pFunctionBase)
// {

// 	// detect Bitdefender EDR hook
// 	// if first byte is JMP, then function is hooked
// 	if(*(PBYTE)pFunctionBase == 0xE9)
// 	{
// 		// e9 0b 02 18 00 == jmp QWORD PTR
// 		// E9 ?? ?? ?? ?? == sig

// 		// check surround exports
// 		// ntdll exports are spaced 0x20 bytes apart
// 		PVOID pPrevExport = (PBYTE)pFunctionBase - 0x20;
// 		PVOID pNextExport = (PBYTE)pFunctionBase + 0x20;


// 	return 0;
// }

// 	return FALSE;
// }

// __forceinline _NODISCARD DWORD Syscall::getSSN(PVOID pFunctionBase)
// {
// 	constexpr BYTE syscallSignature[] = {
// 		0x4c, 0x8b, 0xd1, // mov r10, rcx
// 		0xb8, // mov eax, ? ? ? ?
// 	};


// 	// parse for EAX value

// 	BYTE ssn = 0;
// 	for(auto i = 0; i < 0x20; i++)
// 	{
// 		PBYTE pCurrentByte = (PBYTE)pFunctionBase + i;
// 		if(memcmp(pCurrentByte, syscallSignature, sizeof(syscallSignature)) == 0)
// 		{
// 			ssn = *(PBYTE)(pCurrentByte + sizeof(syscallSignature));
// 			break;
// 		}
// 	}


// 	return ssn;
// }
