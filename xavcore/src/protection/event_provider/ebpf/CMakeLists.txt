# VMLinux header.
set(VMLINUX_HEADER ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
add_custom_command(
    OUTPUT ${VMLINUX_HEADER}
    
    COMMAND
        sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER}

    USES_TERMINAL
)
add_custom_target(vmlinux_header DEPENDS ${VMLINUX_HEADER})

# eBPF objects.
set(
    EBPF_OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/ebpf_event_provider.bpf.o
)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|X86_64|AMD64")
    set(EBPF_TARGET_ARCH __TARGET_ARCH_x86_64)
else()
    message(FATAL_ERROR "Target not supported")
endif()
add_custom_command(
    OUTPUT ${EBPF_OUTPUT}

    COMMAND clang
        -target bpf
        -O2
        -g
        -c ${CMAKE_CURRENT_SOURCE_DIR}/ebpf_event_provider.bpf.c
        -o ${EBPF_OUTPUT}
        -D ${EBPF_TARGET_ARCH}
        -I${CMAKE_CURRENT_BINARY_DIR}
        -I${CMAKE_SOURCE_DIR}/src/include

    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ebpf_event_provider.bpf.c
)
add_custom_target(
    ebpf_event_provider_obj
    DEPENDS ${EBPF_OUTPUT}
)
add_dependencies(ebpf_event_provider_obj vmlinux_header)

# Skeleton header.
set(
    SKELETON_HEADER
    ${CMAKE_CURRENT_BINARY_DIR}/ebpf_event_provider.skel.h
)
add_custom_command(
    OUTPUT ${SKELETON_HEADER}

    COMMAND sudo bpftool gen skeleton ${EBPF_OUTPUT} > ${SKELETON_HEADER}

    DEPENDS ${EBPF_OUTPUT}

    USES_TERMINAL
)
add_custom_target(
    ebpf_event_provider_skeleton_header
    DEPENDS ${SKELETON_HEADER}
)
add_dependencies(ebpf_event_provider_skeleton_header ebpf_event_provider_obj)

add_library(ebpf_event_provider SHARED)
target_sources(ebpf_event_provider PRIVATE ebpf_event_provider.cpp)
add_dependencies(ebpf_event_provider ebpf_event_provider_skeleton_header)
target_include_directories(ebpf_event_provider PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ebpf_event_provider
    PUBLIC
    xavcore_includes elf bpf z httplib::httplib
    spdlog::spdlog
    pfs
    concurrentqueue::concurrentqueue
)
