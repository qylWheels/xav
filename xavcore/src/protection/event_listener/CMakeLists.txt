add_library(levenshtein SHARED levenshtein.cpp)
target_link_libraries(levenshtein
    PUBLIC
    xavcore_includes
    protection
    outcome::hl
)

add_library(event_listener SHARED)
target_link_libraries(event_listener PUBLIC levenshtein)
