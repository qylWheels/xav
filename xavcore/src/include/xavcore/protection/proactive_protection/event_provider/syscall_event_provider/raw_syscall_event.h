#pragma once

#if defined(__BPF__) || defined(__bpf__)
#include "vmlinux.h"
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 i32;
typedef __s64 i64;
#else
#include <cstdint>
typedef std::uint8_t u8;
typedef std::uint32_t u32;
typedef std::uint64_t u64;
typedef std::int32_t i32;
typedef std::int64_t i64;
#endif  // __BPF__, __bpf__

struct __attribute__((packed)) RawSyscallEvent {
    u8 enter_captured;
    u8 exit_captured;

    // Event timestamp.
    // This is the time elapsed since system boot, in nanoseconds.
    // Does include the time the system was suspended.
    u64 timestamp;

    // Process information.
    u32 pid;
    // Boot based time in nanoseconds. Includes the time the system was
    // suspended.
    u64 proc_start_boottime;

    // Syscall information.
    u32 syscall_id;
    u64 args[6];
    u64 ret;

    // Additional strings.
    u8 additional_str_count;
    u8 additional_strs[];
};
