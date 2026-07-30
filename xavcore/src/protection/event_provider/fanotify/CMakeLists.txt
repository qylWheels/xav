add_library(fanotify SHARED)
target_sources(fanotify PRIVATE fanotify_monitor.cpp)
target_link_libraries(fanotify PUBLIC xavagent_includes spdlog::spdlog)
