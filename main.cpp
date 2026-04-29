#define CRAWLR_DEBUG

#include "Crawlr/Crawlr.hpp"
#include <iostream>

int main()
{
    // load ntdll
    auto ntdll = Crawlr::Module(L"ntdll.dll");
    if(auto res = ntdll.load(); !res)
    {
        std::cout << "ERR: " << res.error() << std::endl;
        exit(1);
    }

    auto exports =
        ntdll.parseExports({ "NtAllocateVirtualMemory" /*, "NtOpenProcess"*/ });

    if(!exports.has_value())
    {
        std::cout << "ERR: " << exports.error() << std::endl;
        exit(1);
    }

    // confirm syscall found
    Crawlr::Syscall* NtAllocateVirtualMemory =
        ntdll.getSyscall("NtAllocateVirtualMemory");

    if(NtAllocateVirtualMemory == nullptr)
    {
        std::wcout << "Could not find syscall, aborting\n";
        exit(1);
    }
    std::wcout << "Found syscall: NtAllocateVirtualMemory at "
               << NtAllocateVirtualMemory->getBaseAddress() << std::endl;

    // setup and call syscall
    void* baseAddress = nullptr;
    SIZE_T regionSize = 0x1000;
    NTSTATUS status   = NtAllocateVirtualMemory->invoke<NTSTATUS>(
        (HANDLE)(LONG_PTR)-1,  // NtCurrentProcess()
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    // verify success
    if(status != 0)
    {
        std::wcout << L"Syscall failed with status: " << std::hex << status << std::dec
                   << std::endl;
        exit(1);
    }
    else
    {
        std::wcout << L"Successfully allocated memory at: " << baseAddress << std::endl;
    }

    // test that memory is actually usable
    if(baseAddress)
    {
        char* p = static_cast<char*>(baseAddress);
        p[0]    = 'H';
        p[1]    = 'i';
        p[2]    = '\0';
        std::cout << "Wrote to allocated memory: " << p << std::endl;
    }
}
