add_rules("mode.debug", "mode.release")

set_languages("c++20")

add_requires(
    "leveldb", "cryptopp", "protobuf-cpp", "wxwidgets",
    "oatpp", "spdlog", "yaml-cpp", "openssl"
)
add_requires("vcpkg::yara", {alias = "yara"})

includes("xavcommon")
includes("xavagent")
includes("xavlib")
