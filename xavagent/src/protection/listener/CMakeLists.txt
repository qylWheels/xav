add_library(levenshtein levenshtein.cpp)
target_link_libraries(levenshtein
    PUBLIC
    xavagent_includes
    protection
    outcome::hl
)
