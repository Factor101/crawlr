#include <iostream>
#include "Crawlr/Crawlr.hpp"

int main()
{
    auto modules = Crawlr::ModuleExports();
    auto ntdll = modules.addModule(L"ntdll.dll");
    if(!ntdll)
    {
        std::cout << "ERR" << std::endl;
        return 1;
    }

    auto exportMap = modules.mapExports(*ntdll, { "NtOpenProcess", "NtVirtualAllocEx" });


}
