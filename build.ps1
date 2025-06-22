# build.ps1
$QtPath = "C:\Qt\6.5.0\msvc2019_64"

mkdir build
cd build

cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="$QtPath/lib/cmake"
cmake --build . --config Release

# 运行应用
./Release/HalloChat-Qt.exe