add_library(doctest INTERFACE)
target_include_directories(doctest INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/doctest
)

# unit test files (including main.cpp doctest stub)
add_executable(crawlr_unit_tests
    main.cpp
    unit/Signature_test.cpp
)

target_link_libraries(crawlr_unit_tests PRIVATE crawlr doctest)
add_test(NAME unit COMMAND crawlr_unit_tests)
set_tests_properties(unit PROPERTIES LABELS "unit")

# integration test files
add_executable(crawlr_integration_tests
    main.cpp
    integration/SyscallInvocation_test.cpp)

target_link_libraries(crawlr_integration_tests PRIVATE crawlr doctest)
add_test(NAME integration COMMAND crawlr_integration_tests)
set_tests_properties(integration PROPERTIES LABELS "integration")
