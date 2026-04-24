#include "Crawlr/Crawlr.hpp"
#include <iostream>

int main()
{
    auto modules = Crawlr::ModuleExports();
    auto ntdll   = modules.addModule(L"ntdll.dll");
    if(auto res = ntdll.load(); !res)
    {
        std::cout << "ERR: " << res.error() << std::endl;
        return 1;
    }

    auto meminfo = ntdll.getMemoryInfo();
    std::wcout << L"Module: " << ntdll.getModuleName() << std::endl;
    std::wcout << L"Base Address: " << meminfo.baseAddress << std::endl;
    std::wcout << L"Image Size: " << meminfo.imageSize << " bytes" << std::endl;

    auto exports = ntdll.parseExports({ "NtOpenProcess", "NtAllocateVirtualMemory" });

    if(!exports.has_value())
    {
        std::cout << "ERR: " << exports.error() << std::endl;
        return 1;
    }

    for(const auto& [name, exp] : ntdll.getExports())
    {
        std::wcout << L"Export: " << name.c_str() << std::endl;
        std::wcout << L"Address: " << exp.getBaseAddress() << std::endl;
        std::wcout << L"Size: " << exp.getSize() << " bytes" << std::endl;
    }



}
