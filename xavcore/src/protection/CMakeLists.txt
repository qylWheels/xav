# Subdirectories.
add_subdirectory(hips)
add_subdirectory(on_access_scanning)
add_subdirectory(proactive_protection)

# VMLinux header.
set(VMLINUX_HEADER ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
add_custom_command(
    OUTPUT ${VMLINUX_HEADER}
    
    COMMAND
        sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER}

    USES_TERMINAL
)
add_custom_target(vmlinux_header DEPENDS ${VMLINUX_HEADER})

# Process status viewer.
add_library(process_status_viewer SHARED process_status_viewer.cpp)
target_link_libraries(
    process_status_viewer PUBLIC
    xavcore_includes pfs spdlog::spdlog outcome::hl
    process_lifecycle_event_provider
)
