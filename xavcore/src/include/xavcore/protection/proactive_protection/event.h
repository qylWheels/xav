#pragma once

#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

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
