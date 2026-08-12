#pragma once

#if defined(__BPF__) || defined(__bpf__)
#include "vmlinux.h"
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
#else
#include <cstdint>
typedef std::uint8_t u8;
typedef std::uint32_t u32;
typedef std::uint64_t u64;
#endif  // __BPF__, __bpf__

struct __attribute__((packed)) RawProcessCreateEvent {
    u32 pid;
};

struct __attribute__((packed)) RawProcessExitEvent {
    u32 pid;
};

struct __attribute__((packed)) RawProcessLifecycleEvent {
    u64 start_time;
    u8 tag;  // 0 = create, 1 = exit
    union {
        struct RawProcessCreateEvent create;
        struct RawProcessExitEvent exit;
    } u;
};
