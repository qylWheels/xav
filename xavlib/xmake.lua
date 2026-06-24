add_requires("leveldb", "cryptopp")

target("xavlib")
    set_kind("shared")
    add_files("*.cpp")
    add_packages("leveldb", "cryptopp")
