#include "Crawlr/Crawlr.hpp"
#include <doctest/doctest.h>
#include <ios>
#include <memoryapi.h>

TEST_CASE("Unhooked Syscall is invoked - ntdll!NtAllocateVirtualMemory")
{
    const wchar_t* MODULE_NAME = L"ntdll.dll";
    const std::string SYSCALL_NAME = "NtAllocateVirtualMemory";

    Crawlr::Module ntdll{ MODULE_NAME };

    auto loadResult = ntdll.load();
    REQUIRE(loadResult.has_value());

    auto exportResult = ntdll.parseExports({ SYSCALL_NAME });
    if(!exportResult)
    {
        FAIL("Export parse failed:" << exportResult.error());
    }

    Crawlr::Syscall* sc = ntdll.getSyscall(SYSCALL_NAME);
    if(sc == nullptr)
    {
        MESSAGE("ntdll!NtAllocateVirtualMemory's stub is likely hooked."
                "Skipping unhooked invocation test.");
        return;
    }

    const SIZE_T INITIAL_REGION_SIZE = 0x1000;  // request 1 full page
    SIZE_T regionSize = INITIAL_REGION_SIZE;
    void* base = nullptr;

    NTSTATUS status = sc->invoke<NTSTATUS>(
        (HANDLE)(LONG_PTR)-1,  // NtCurrentProcess
        &base,
        (ULONG_PTR)0,          // ZeroBits
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    CAPTURE(base);
    CAPTURE(regionSize);

    REQUIRE_MESSAGE(status == 0, "NTSTATUS 0x" << std::hex << status);
    CHECK(base != nullptr);
    CHECK(regionSize >= INITIAL_REGION_SIZE);

    INFO("Verifying allocated memory properties");
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T mbiSize = VirtualQuery(base, &mbi, sizeof(mbi));

    REQUIRE(mbiSize == sizeof(mbi));
    CHECK(mbi.State == MEM_COMMIT);
    CHECK(mbi.Protect == PAGE_READWRITE);
    CHECK(mbi.RegionSize >= INITIAL_REGION_SIZE);

    INFO("Verifying RW access");
    auto* p = static_cast<uint8_t*>(base);
    p[0] = 0xFF;
    CHECK(*p == 0xFF);

    // End of test; release memory
    VirtualFree(base, 0, MEM_RELEASE);
}
