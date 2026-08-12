#pragma once

#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace xavcore {
struct Process {
    // Unnullable fields.
    std::uint32_t pid;
    std::chrono::time_point<std::chrono::system_clock> start_time;

    // Nullable fields.
    std::optional<std::uint32_t> ppid;
    std::optional<std::filesystem::path> exe_path;
    std::optional<std::string> cmdline;

    bool operator==(const Process& other) const {
        return pid == other.pid && start_time == other.start_time;
    }
};

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
        seed ^=
            std::hash<std::uint64_t>()(p.start_time.time_since_epoch().count());
        return seed;
    }
};
}  // namespace std
