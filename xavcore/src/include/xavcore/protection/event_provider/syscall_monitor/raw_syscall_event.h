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

struct __attribute__((packed)) RawSyscallEvent {
    u8 enter_captured;
    u8 exit_captured;

    u32 pid;
    u32 syscall_id;
    u64 args[6];
    u64 ret;
};

#ifdef __cplusplus
static_assert(sizeof(RawSyscallEvent) == 66,
              "RawSyscallEvent size is not 66 bytes");
#else
_Static_assert(sizeof(RawSyscallEvent) == 66,
               "RawSyscallEvent size is not 66 bytes");
#endif  // __cplusplus
