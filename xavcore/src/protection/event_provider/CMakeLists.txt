# Subdirectories.
# add_subdirectory(fanotify)
add_subdirectory(ebpf)

add_library(event_provider INTERFACE)
target_link_libraries(event_provider INTERFACE ebpf_event_provider)
