add_library(crawlr STATIC
    src/Module.cpp
    src/ModuleExports.cpp
    src/ModuleParser.cpp
    src/Signature.cpp
    src/SyscallParser.cpp
    src/HookAnalysis.cpp
    src/SyscallLibrary.cpp
    src/Syscall.cpp
)

target_include_directories(crawlr
    PUBLIC
        ${CMAKE_SOURCE_DIR}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/extern
)

target_compile_definitions(crawlr
    PRIVATE
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
)
