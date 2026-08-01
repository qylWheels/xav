add_subdirectory(event_provider)
add_subdirectory(event_listener)

add_library(proactive_protection SHARED)
target_link_libraries(
    proactive_protection PUBLIC
    event_provider event_listener
)
