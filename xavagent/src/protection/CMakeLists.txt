# Subdirectories.
add_subdirectory(event_provider)
add_subdirectory(event_listener)

add_library(protection SHARED)
target_sources(protection PRIVATE
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
