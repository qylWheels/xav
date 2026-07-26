# Subdirectories.
add_subdirectory(event_collection)

add_library(protection SHARED)
target_sources(protection PRIVATE
    levenshtein_similarity.cpp
    on_access_scanner.cpp
)
target_link_libraries(
    protection PUBLIC
    rapidfuzz::rapidfuzz
    protobufs
    listener
    spdlog::spdlog
    outcome::hl
)
target_link_libraries(protection PUBLIC xavagent_includes)
