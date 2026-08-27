cmake_minimum_required(VERSION 3.20)

project(xavcore)

# Common settings.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Packages from vcpkg.
find_path(MLPACK_INCLUDE_DIRS "mlpack.hpp")
find_path(BEXT_SML_INCLUDE_DIRS "boost/sml.hpp")
find_package(leveldb CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(outcome CONFIG REQUIRED)
find_package(rapidfuzz CONFIG REQUIRED)
find_package(cpptrace CONFIG REQUIRED)
find_package(protobuf CONFIG REQUIRED)
find_package(cryptopp CONFIG REQUIRED)
find_package(httplib CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(concurrentqueue CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(boost_container_hash CONFIG REQUIRED)
pkg_check_modules(YARA REQUIRED IMPORTED_TARGET yara)

# Packages from cmake.
include(FetchContent)
set(pfs_BUILD_SHARED_LIBS ON CACHE BOOL "Build shared library for pfs" FORCE)
FetchContent_Declare(
  pfs
  GIT_REPOSITORY https://github.com/dtrugman/pfs.git
  GIT_TAG        v0.15.0
)
FetchContent_MakeAvailable(pfs)

# Subdirectories.
add_subdirectory(src)

# Include directories.
add_library(xavcore_includes INTERFACE)
target_include_directories(xavcore_includes INTERFACE
    ${PROJECT_SOURCE_DIR}/src/include
)
