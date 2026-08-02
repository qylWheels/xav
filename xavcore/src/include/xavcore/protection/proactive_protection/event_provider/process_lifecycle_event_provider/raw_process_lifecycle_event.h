#pragma once

#if defined(__BPF__) || defined(__bpf__)
#include "vmlinux.h"
typedef __u32 u32;
#else
#include <cstdint>
typedef std::uint32_t u32;
#endif  // __BPF__, __bpf__

struct __attribute__((packed)) RawProcessCreateEvent {
    u32 pid;
};

struct __attribute__((packed)) RawProcessExitEvent {
    u32 pid;
};

#ifdef __cplusplus
static_assert(sizeof(RawProcessCreateEvent) == 4,
              "RawProcessCreateEvent size is not 4 bytes");
static_assert(sizeof(RawProcessExitEvent) == 4,
              "RawProcessExitEvent size is not 4 bytes");
#else
_Static_assert(sizeof(struct RawProcessCreateEvent) == 4,
               "RawProcessCreateEvent size is not 4 bytes");
_Static_assert(sizeof(struct RawProcessExitEvent) == 4,
               "RawProcessExitEvent size is not 4 bytes");
#endif  // __cplusplus
