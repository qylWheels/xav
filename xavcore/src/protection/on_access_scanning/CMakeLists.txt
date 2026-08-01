add_library(on_access_scanning SHARED)
target_sources(on_access_scanning PRIVATE
    on_access_scanner.cpp
)
target_link_libraries(
    on_access_scanning PUBLIC
    rapidfuzz::rapidfuzz
    protobufs
    spdlog::spdlog
    outcome::hl
)
target_link_libraries(on_access_scanning PUBLIC xavcore_includes)
