add_rules("mode.debug", "mode.release")

set_languages("c++20")

add_requires(
    "leveldb", "cryptopp", "protobuf-cpp", "wxwidgets",
    "oatpp", "spdlog", "yaml-cpp", "openssl", "outcome",
    "rapidfuzz", "cpptrace"
)
add_requires("apt::libyara-dev", {alias = "yara"})
add_requires("vcpkg::boost-beast", {alias = "boost-beast"})

includes("xavcommon")
includes("xavagent")
includes("xavlib")
