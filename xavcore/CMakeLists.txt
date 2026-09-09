cmake_minimum_required(VERSION 3.20)

project(xavcore)

# Common settings.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# RPATH policy for packaging.
#
# All xavcore libraries install into ${prefix}/lib and the executables into
# ${prefix}/bin, both searched by the dynamic loader by default, so no RPATH
# is needed in the packaged binaries.  We therefore:
#   - link with the (empty) install RPATH instead of absolute build-tree paths
#     (CMAKE_BUILD_WITH_INSTALL_RPATH), so no build directory leaks in, and
#   - skip CMake's install-time RPATH rewriting (CMAKE_SKIP_INSTALL_RPATH).
#   Without this, installing a .so whose build RPATH is a single directory
#   fails CMake's "file RPATH_CHANGE" step (it compares against "<dir>:").
# Trade-off: running the modules straight out of build/ now needs the libs on
# LD_LIBRARY_PATH.
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
set(CMAKE_SKIP_INSTALL_RPATH ON)

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
add_subdirectory(test)

# Include directories.
add_library(xavcore_includes INTERFACE)
target_include_directories(xavcore_includes INTERFACE
    ${PROJECT_SOURCE_DIR}/src/include
)

# Libraries: every SHARED library we build goes to ${prefix}/lib.
install(
    TARGETS
        types
        cache
        scan
        protobufs
        hips_monitor
        syscall_event_provider
        on_access_scanning
        placeholder_event_listener
        anomalous_syscall_detection_listener
        rule_based_detection_listener
        proactive_protection_rules
    LIBRARY DESTINATION lib        # ${prefix}/lib/lib*.so
)

# Executables: the runtime service binaries go to ${prefix}/bin.
install(
    TARGETS
        xavcore_on_access_scanning_module
        xavcore_proactive_protection_module
    RUNTIME DESTINATION bin        # ${prefix}/bin/<name>
)

# Public headers: copy the whole src/include/xavcore tree, preserving layout,
# into ${prefix}/include/xavcore.
install(
    DIRECTORY ${PROJECT_SOURCE_DIR}/src/include/xavcore
    DESTINATION include
)

# CPack.
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_PACKAGE_NAME "xavcore")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "qylWheels <command1748165360@126.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Xav core components")

# DKMS control scripts.
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    ${PROJECT_SOURCE_DIR}/packaging/postinst
    ${PROJECT_SOURCE_DIR}/packaging/prerm
)

# Runtime dependencies needed so the DKMS build can succeed on the target.
set(CPACK_DEBIAN_PACKAGE_DEPENDS
    "dkms (>= 3.0), gcc, make, linux-headers-amd64"
)

include(CPack)
