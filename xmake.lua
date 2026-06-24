add_rules("mode.debug", "mode.release")

set_languages("c++20")

add_requires("leveldb", "cryptopp")

includes("xavcli")
includes("xavlib")
