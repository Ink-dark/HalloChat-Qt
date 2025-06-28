cmake_minimum_required(VERSION 3.16)

# 集成测试可执行文件
add_executable(integration_tests
    test_domain_protocol.cpp
    test_crypto_adapter.cpp
)

# 链接测试库和项目核心库
target_link_libraries(integration_tests PRIVATE
    gtest
    gtest_main
    HalloChatCore
)

# 添加到CTest
add_test(NAME integration_tests COMMAND integration_tests)

# 包含项目头文件
target_include_directories(integration_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)