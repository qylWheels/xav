# Subdirectories.
# add_subdirectory(fanotify)
add_subdirectory(syscall_monitor)

add_library(event_collection INTERFACE)
target_link_libraries(event_collection INTERFACE syscall_monitor)
