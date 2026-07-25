add_library(scan SHARED)
target_sources(scan PRIVATE
    exact_hash.cpp scanner.cpp
    static_heuristic.cpp yara_static_heuristic_engine.cpp
)
target_link_libraries(scan PUBLIC cryptopp::cryptopp)
target_link_libraries(scan PUBLIC outcome::hl)
target_link_libraries(scan PUBLIC protobufs)
target_link_libraries(scan PUBLIC PkgConfig::YARA)
target_link_libraries(scan PUBLIC xavagent_includes)
target_link_libraries(scan
    PUBLIC
    spdlog::spdlog leveldb::leveldb
)
