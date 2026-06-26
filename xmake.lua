add_rules("mode.debug", "mode.release")

set_languages("c++20")

add_requires("leveldb", "cryptopp", "protobuf-cpp", "fltk")

includes("xavgui")
includes("xavlib")
