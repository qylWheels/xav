#pragma once

#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>

namespace xavcore {
struct Process {
    std::optional<std::uint32_t> pid;
    std::optional<std::uint32_t> ppid;
    std::optional<std::uint64_t> start_time_tick;
    std::optional<std::filesystem::path> exe_path;
    std::optional<std::string> cmdline;

    bool operator==(const Process& other) const {
        return pid == other.pid && start_time_tick == other.start_time_tick;
    }
};

struct FileCreateEventPayload {
    std::filesystem::path path;
};

struct FileDeleteEventPayload {
    std::filesystem::path path;
};

struct FileReadEventPayload {
    std::filesystem::path path;
};

struct FileWriteEventPayload {
    std::filesystem::path path;
};

struct FileRenameEventPayload {
    std::filesystem::path oldpath;
    std::filesystem::path newpath;
};

struct FileAttributeChangeEventPayload {
    std::filesystem::path path;
};

struct FileEvent {
    Process process;
    std::variant<FileCreateEventPayload, FileDeleteEventPayload,
                 FileReadEventPayload, FileWriteEventPayload,
                 FileRenameEventPayload, FileAttributeChangeEventPayload>
        payload;
};

struct ProcessCreateEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    std::uint32_t pid;
};

struct ProcessExitEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    std::uint32_t pid;
};

using ProcessLifecycleEvent =
    std::variant<ProcessCreateEvent, ProcessExitEvent>;

using Event = std::variant<SyscallEvent, ProcessLifecycleEvent, FileEvent>;

class IEvent {
public:
    virtual ~IEvent() = default;
};
}  // namespace xavcore

namespace std {
template <>
struct hash<xavcore::Process> {
    std::size_t operator()(const xavcore::Process& p) const {
        std::size_t seed = std::hash<std::optional<std::int64_t>>{}(p.pid);
        if (p.start_time_tick.has_value()) {
            seed ^= std::hash<std::uint64_t>()(p.start_time_tick.value());
        }
        return seed;
    }
};
}  // namespace std
