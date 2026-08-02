#pragma once

#if defined(__BPF__) || defined(__bpf__)
#include "vmlinux.h"
typedef __u8 u8;
typedef __u32 u32;
#else
#include <cstdint>
typedef std::uint8_t u8;
typedef std::uint32_t u32;
#endif  // __BPF__, __bpf__

struct __attribute__((packed)) RawProcessCreateEvent {
    u32 pid;
};

struct __attribute__((packed)) RawProcessExitEvent {
    u32 pid;
};

struct __attribute__((packed)) RawProcessLifecycleEvent {
    u8 tag;  // 0 = create, 1 = exit
    union {
        struct RawProcessCreateEvent create;
        struct RawProcessExitEvent exit;
    } u;
};

#ifdef __cplusplus
static_assert(sizeof(RawProcessCreateEvent) == 4,
              "RawProcessCreateEvent size is not 4 bytes");
static_assert(sizeof(RawProcessExitEvent) == 4,
              "RawProcessExitEvent size is not 4 bytes");
static_assert(sizeof(RawProcessLifecycleEvent) == 5,
              "RawProcessLifecycleEvent size is not 5 bytes");
#else
_Static_assert(sizeof(struct RawProcessCreateEvent) == 4,
               "RawProcessCreateEvent size is not 4 bytes");
_Static_assert(sizeof(struct RawProcessExitEvent) == 4,
               "RawProcessExitEvent size is not 4 bytes");
_Static_assert(sizeof(struct RawProcessLifecycleEvent) == 5,
               "RawProcessLifecycleEvent size is not 5 bytes");
#endif  // __cplusplus
