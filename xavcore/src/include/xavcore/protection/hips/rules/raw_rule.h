#pragma once

#if defined(__BPF__) || defined(__bpf__)
#include "vmlinux.h"
typedef _Bool bool;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 i32;
typedef __s64 i64;
#else
#include <cstdint>
typedef std::uint8_t u8;
typedef std::uint16_t u16;
typedef std::uint32_t u32;
typedef std::uint64_t u64;
typedef std::int32_t i32;
typedef std::int64_t i64;
#endif  // __BPF__, __bpf__

#define MAX_NAME_LEN (128)
#define MAX_PATH_LEN (768)

struct __attribute__((packed)) Rule {
    char name[MAX_NAME_LEN];
    bool enabled;
    bool allow;
    bool kill_process;
    u16 priority;
    char trigger[MAX_PATH_LEN];
};

enum FileEventType {
    CREATE = 1 << 0,
    DELETE = 1 << 1,
    READ = 1 << 2,
    WRITE = 1 << 3,
    EXECUTE = 1 << 4,
};

struct __attribute__((packed)) FileRule {
    struct Rule rule;
    enum FileEventType event_type;
    char path[MAX_PATH_LEN];
};
