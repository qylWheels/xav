#pragma once

#if defined(__BPF__) || defined(__bpf__)
#include "vmlinux.h"
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 i8;
typedef __s32 i32;
typedef __s64 i64;
#else
#include <cstdint>
typedef std::uint8_t u8;
typedef std::uint16_t u16;
typedef std::uint32_t u32;
typedef std::uint64_t u64;
typedef std::int8_t i8;
typedef std::int32_t i32;
typedef std::int64_t i64;
#endif  // __BPF__, __bpf__

#define MAX_GROUP_NAME_LEN (48)
#define MAX_NAME_LEN (128)
#define MAX_PATH_LEN (512)
#define MAX_PATTERN_LEN (MAX_PATH_LEN / 4)

struct __attribute__((packed)) RuleIdentifier {
    char group_name[MAX_GROUP_NAME_LEN];
    char name[MAX_NAME_LEN];
};

struct __attribute__((packed)) Rule {
    struct RuleIdentifier id;
    u8 enabled;
    u8 allow;
    u8 kill_process;
    i8 priority;
    char trigger[MAX_PATTERN_LEN];
    u8 use_wildcard_in_trigger;
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
    char path[MAX_PATTERN_LEN];
    u8 use_wildcard_in_path;
};
