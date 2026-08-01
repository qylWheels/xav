# Subdirectories.
# add_subdirectory(fanotify)
add_subdirectory(syscall_event_provider)

add_library(event_provider INTERFACE)
target_link_libraries(event_provider INTERFACE syscall_event_provider)
