#pragma once

#include <unistd.h>

#include <bitset>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace xavagent {
struct Process {
    std::optional<std::int64_t> pid;
    std::optional<std::int64_t> ppid;
    std::optional<std::uint64_t> start_time_tick;
    std::optional<std::filesystem::path> exe_path;
    std::optional<std::string> cmdline;

    bool operator==(const Process& other) const {
        return pid == other.pid && start_time_tick == other.start_time_tick;
    }
};

#define FILE_EVENT_TYPE_MASK_SIZE 16

struct FileEvent {
    enum class FileEventType {
        Create,
        Delete,
        Read,
        Write,
        Move,
        AttributeChange,

        Count,
    };
    std::bitset<FILE_EVENT_TYPE_MASK_SIZE> event_type_mask;

    // Who did the operation.
    Process proc;

    // Who is(are) affected by the operation.
    std::string path1;
    std::optional<std::string> path2;

    // Attributes of files.
    std::optional<std::filesystem::file_status> stat1;
    std::optional<std::filesystem::file_status> stat2;
};

struct ReadSyscallEventPayload {
    int fd;
    std::optional<std::filesystem::path> path;
    void* buf;
    std::optional<std::vector<char>> buf_content;
    std::size_t count;
    ::ssize_t ret;
};

using SyscallEventPayload = std::variant<ReadSyscallEventPayload>;

struct Event {
    Process process;
    std::variant<FileEvent, SyscallEventPayload> payload;
};
}  // namespace xavagent

namespace std {
template <>
struct hash<xavagent::Process> {
    std::size_t operator()(const xavagent::Process& p) const {
        std::size_t seed = std::hash<std::optional<std::int64_t>>{}(p.pid);
        if (p.start_time_tick.has_value()) {
            seed ^= std::hash<std::uint64_t>()(p.start_time_tick.value());
        }
        return seed;
    }
};
}  // namespace std
