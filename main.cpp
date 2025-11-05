#include "Crawlr/Crawlr.hpp"
#include <iostream>

int main()
{
    auto modules = Crawlr::ModuleExports();
    auto ntdll   = modules.addModule(L"ntdll.dll");
    if (auto res = ntdll.load(); !res.success)
    {
        std::cout << "ERR: " << res.error << std::endl;
        return 1;
    }

    auto exportMap = modules.mapExports(*ntdll, { "NtOpenProcess", "NtVirtualAllocEx" });
}
