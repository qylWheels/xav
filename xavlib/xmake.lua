add_requires("leveldb")

target("xavlib")
    set_kind("shared")
    add_files("*.cpp")
    add_packages("leveldb")
