add_library(placeholder_event_listener SHARED placeholder_event_listener.cpp)
target_link_libraries(
    placeholder_event_listener PUBLIC
    xavcore_includes
)
