# Subdirectories.
add_subdirectory(provider)
add_subdirectory(listener)

add_library(protection SHARED)
target_sources(protection PRIVATE
    levenshtein_similarity.cpp
    on_access_scanner.cpp
)
target_link_libraries(
    protection PUBLIC
    rapidfuzz::rapidfuzz
    protobufs
    provider
    listener
    spdlog::spdlog
    outcome::hl
)
target_link_libraries(protection PUBLIC xavagent_includes)
