add_rules("mode.debug", "mode.release")

set_languages("c++20")

add_requires(
    "leveldb", "cryptopp", "protobuf-cpp", "wxwidgets",
    "oatpp", "spdlog"
)

includes("xavagent")
includes("xavlib")
