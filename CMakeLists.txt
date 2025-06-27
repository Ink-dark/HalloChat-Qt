cmake_minimum_required(VERSION 3.16)
project(HalloChat-Qt VERSION 0.1.1 LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick Network WebSockets)

qt_add_executable(HalloChat-Qt
    src/main.cpp
    src/DatabaseManager.cpp
    src/DatabaseManager.h
)

qt_add_resources(HalloChat-Qt "qml-resources"
    PREFIX "/"
    FILES
        qml/App.qml
)

qt_add_qml_module(HalloChat-Qt
    URI HalloChat
    VERSION 1.0
    QML_FILES
        qml/App.qml
)

include_directories(src)

// 添加密码安全库
find_package(PkgConfig REQUIRED)
pkg_check_modules(ARGON2 REQUIRED libargon2)
pkg_check_modules(SODIUM REQUIRED libsodium)

target_link_libraries(HalloChat-Qt PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::Network
    Qt6::WebSockets
    ${ARGON2_LIBRARIES}
    ${SODIUM_LIBRARIES}
)

if(WIN32)
    add_custom_command(TARGET HalloChat-Qt POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            $<TARGET_FILE_DIR:HalloChat-Qt>/sqldrivers
        COMMAND ${CMAKE_COMMAND} -E copy
            $<TARGET_FILE_DIR:Qt6::Core>/../plugins/sqldrivers/qsqlite.dll
            $<TARGET_FILE_DIR:HalloChat-Qt>/sqldrivers
    )
endif()

# 复制SQLite数据库文件到构建目录
add_custom_command(TARGET HalloChat-Qt POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_SOURCE_DIR}/database/chat.db
    $<TARGET_FILE_DIR:HalloChat-Qt>/chat.db
)