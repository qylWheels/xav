add_rules("mode.debug", "mode.release")

set_languages("c++20")

add_requires(
    "leveldb", "cryptopp", "protobuf-cpp",
    "oatpp", "spdlog", "yaml-cpp", "openssl", "outcome",
    "rapidfuzz", "cpptrace"
)
add_requires("apt::libyara-dev", {alias = "yara"})
add_requires("vcpkg::boost-beast", {alias = "boost-beast"})

add_includedirs("$(projectdir)")

includes("edr/behavioral_protection/syscall_monitor/ebpf")

target("xavagent")
    set_kind("binary")
    add_files("**.cpp")
    add_packages(
        "leveldb", "cryptopp", "wxwidgets", "oatpp", "protobuf-cpp",
        "spdlog", "yaml-cpp", "yara", "outcome", "rapidfuzz", "cpptrace",
        "boost-beast"
    )
    add_deps("syscall_monitor")

