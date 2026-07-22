add_library(fanotify SHARED)
target_sources(fanotify PRIVATE fanotify_monitor.cpp)
