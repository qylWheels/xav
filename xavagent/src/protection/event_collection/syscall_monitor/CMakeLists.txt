# VMLinux header.
set(VMLINUX_HEADER ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
add_custom_command(
    OUTPUT ${VMLINUX_HEADER}
    
    COMMAND
        sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER}
)
add_custom_target(vmlinux_header DEPENDS ${VMLINUX_HEADER})

# eBPF objects.
set(
    EBPF_OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/syscall_monitor.bpf.o
)
add_custom_command(
    OUTPUT ${EBPF_OUTPUT}

    COMMAND clang
        -target bpf
        -O2
        -g
        -c syscall_monitor.bpf.c
        -o ${EBPF_OUTPUT}

    DEPENDS syscall_monitor.bpf.c
)
add_custom_target(
    syscall_monitor_ebpf
    DEPENDS ${EBPF_OUTPUT}
)
add_dependencies(syscall_monitor_ebpf vmlinux_header)

# Skeleton header.
set(
    SKELETON_HEADER
    ${CMAKE_CURRENT_BINARY_DIR}/syscall_monitor.skel.h
)
add_custom_command(
    OUTPUT ${SKELETON_HEADER}

    COMMAND bpftool gen skeleton ${EBPF_OUTPUT} > ${SKELETON_HEADER}

    DEPENDS ${EBPF_OUTPUT}
)
add_custom_target(
    syscall_monitor_skeleton_header
    DEPENDS ${SKELETON_HEADER}
)
add_dependencies(syscall_monitor_skeleton_header syscall_monitor_ebpf)

add_library(syscall_monitor SHARED)
target_sources(syscall_monitor PRIVATE syscall_monitor.cpp)
add_dependencies(syscall_monitor syscall_monitor_skeleton_header)
target_include_directories(syscall_monitor PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(syscall_monitor PUBLIC xavagent_includes elf bpf z)
