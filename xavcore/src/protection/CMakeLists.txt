# Subdirectories.
add_subdirectory(on_access_scanning)
add_subdirectory(proactive_protection)

add_library(protection SHARED)
target_link_libraries(
    protection PUBLIC
    on_access_scanning proactive_protection
)
