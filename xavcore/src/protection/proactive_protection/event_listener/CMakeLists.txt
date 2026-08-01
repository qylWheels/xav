add_library(levenshtein SHARED levenshtein.cpp)
target_link_libraries(levenshtein
    PUBLIC
    xavcore_includes
    protection
    outcome::hl
)
