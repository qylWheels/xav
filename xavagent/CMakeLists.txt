cmake_minimum_required(VERSION 3.15)

project(xavagent)

# Common settings.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Subdirectories.
add_subdirectory(src)

# Packages from vcpkg.
find_package(leveldb CONFIG REQUIRED)
find_package(oatpp CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(outcome CONFIG REQUIRED)
find_package(rapidfuzz CONFIG REQUIRED)
find_package(cpptrace CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS beast)
find_package(protobuf CONFIG REQUIRED)
find_package(cryptopp CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(YARA REQUIRED IMPORTED_TARGET yara)
