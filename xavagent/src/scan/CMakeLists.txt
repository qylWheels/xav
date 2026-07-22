find_package(cryptopp CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(YARA REQUIRED IMPORTED_TARGET yara)

add_library(scan SHARED)
target_sources(scan
    exact_hash.cpp scanner.cpp
    static_heuristic.cpp yara_static_heuristic_engine.cpp
)
target_link_libraries(scan PUBLIC cryptopp::cryptopp)
target_link_libraries(scan PUBLIC outcome::hl)
target_link_libraries(scan PUBLIC protobufs)
target_link_libraries(scan PUBLIC global_context)
target_link_libraries(scan PUBLIC PkgConfig::YARA)
