# Subdirectories.
add_subdirectory(event_collection)

add_library(protection SHARED)
target_sources(protection PRIVATE
    behavioral_monitor.cpp levenshtein_similarity.cpp
    on_access_scanner.cpp
)
