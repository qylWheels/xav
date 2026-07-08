#pragma once

#include <bitset>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>

namespace xavagent {
struct Process {
    int pid;
    std::optional<int> ppid;
    std::optional<unsigned long long> start_time_tick;
    std::optional<std::string> exe_path;
    std::optional<std::string> cmdline;

    bool operator==(const Process& other) const {
        return pid == other.pid && ppid == other.ppid &&
               start_time_tick == other.start_time_tick &&
               exe_path == other.exe_path && cmdline == other.cmdline;
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

using Event = std::variant<FileEvent>;
}  // namespace xavagent

namespace std {
template <>
struct hash<xavagent::Process> {
    std::size_t operator()(const xavagent::Process& p) const {
        std::size_t seed = std::hash<int>()(p.pid);
        if (p.start_time_tick.has_value()) {
            seed ^= std::hash<unsigned long long>()(p.start_time_tick.value());
        }
        return seed;
    }
};
}  // namespace std
