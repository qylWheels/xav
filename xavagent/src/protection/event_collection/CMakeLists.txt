# Subdirectories.
add_subdirectory(fanotify)
add_subdirectory(syscall_monitor)

add_library(event_collection SHARED)
target_link_libraries(event_collection PUBLIC fanotify syscall_monitor)
