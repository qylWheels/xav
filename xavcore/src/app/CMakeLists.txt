add_executable(xavcore)
target_sources(xavcore PRIVATE main.cpp)
target_link_libraries(
    xavcore PRIVATE
    xavcore_includes syscall_event_provider placeholder_event_listener
    on_access_scanning process_lifecycle_event_provider
)
target_link_libraries(xavcore PRIVATE scan)
target_link_libraries(xavcore PRIVATE cpptrace::cpptrace)
target_link_libraries(xavcore PRIVATE spdlog::spdlog)
