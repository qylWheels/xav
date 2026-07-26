# Subdirectories.
add_subdirectory(event_collection)

add_library(protection SHARED)
target_sources(protection PRIVATE
    behavior_monitor.cpp levenshtein_similarity.cpp
    on_access_scanner.cpp
)
target_link_libraries(
    protection PUBLIC
    rapidfuzz::rapidfuzz
    protobufs
    spdlog::spdlog
    outcome::hl
)
target_link_libraries(protection PUBLIC xavagent_includes)
