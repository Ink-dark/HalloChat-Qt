#!/bin/bash
set -e

# 跨平台构建脚本：支持Windows(WSL)、macOS、Linux
# 依赖：cmake >= 3.16, Qt6, ninja(可选)

# 创建构建目录
BUILD_DIR="build"
if [ ! -d "$BUILD_DIR" ]; then
    mkdir -p "$BUILD_DIR"
fi
cd "$BUILD_DIR"

# 检测操作系统并设置CMake生成器
OS_NAME=$(uname -s)
case "$OS_NAME" in
    Linux*)
        GENERATOR="Ninja"
        ;;    Darwin*)
        GENERATOR="Xcode"
        ;;    MINGW*|MSYS*|CYGWIN*)
        # Windows (WSL或Git Bash环境)
        GENERATOR="MinGW Makefiles"
        ;;    *)
        echo "不支持的操作系统: $OS_NAME"
        exit 1
        ;;
esac

# 检查是否安装了指定的生成器
if ! cmake --help | grep -q "$GENERATOR"; then
    echo "未找到生成器 $GENERATOR，使用默认生成器"
    GENERATOR=""
fi

# 运行CMake配置
CMAKE_CMD="cmake .. -DCMAKE_BUILD_TYPE=Release"
if [ -n "$GENERATOR" ]; then
    CMAKE_CMD+=" -G \"$GENERATOR\""
fi

echo "运行配置命令: $CMAKE_CMD"
eval $CMAKE_CMD

# 构建项目
echo "开始构建项目..."
cmake --build . --config Release

# 输出构建结果路径
if [ "$OS_NAME" = "Darwin" ]; then
    BINARY_PATH="HalloChat-Qt.app/Contents/MacOS/HalloChat-Qt"
elif [[ "$OS_NAME" == MINGW* || "$OS_NAME" == MSYS* || "$OS_NAME" == CYGWIN* ]]; then
    BINARY_PATH="Release/HalloChat-Qt.exe"
else
    BINARY_PATH="HalloChat-Qt"
fi

if [ -f "$BINARY_PATH" ]; then
    echo "构建成功! 可执行文件路径: $(pwd)/$BINARY_PATH"
else
    echo "构建失败，未找到可执行文件"
    exit 1
fi