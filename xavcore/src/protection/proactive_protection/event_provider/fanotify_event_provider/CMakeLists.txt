add_library(fanotify_event_provider SHARED)
target_sources(fanotify_event_provider PRIVATE fanotify_event_provider.cpp)
target_link_libraries(
    fanotify_event_provider
    PUBLIC
    xavcore_includes spdlog::spdlog pfs
    process_status_viewer
)
