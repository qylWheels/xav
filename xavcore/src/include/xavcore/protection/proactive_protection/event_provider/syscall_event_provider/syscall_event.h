#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <variant>
#include <vector>

#include "xavcore/protection/proactive_protection/event.h"

namespace xavcore {
// Normal syscall event, for those who don't need to parse arguments.
struct SyscallEvent : public IEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    Process process;
    std::uint32_t id;
    std::vector<std::uint64_t> args;
    std::uint64_t ret;
};

struct ReadSyscallEventArgs {
    std::uint32_t fd;
    std::optional<std::filesystem::path> fd_path;

    std::uint64_t buf;
    std::uint64_t count;
};

// Specific syscall events, for those who need to parse arguments.
struct SpecificSyscallEvent : public IEvent {
    // When and who.
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    Process process;

    std::variant<ReadSyscallEventArgs> args;
    std::uint64_t ret;
};
}  // namespace xavcore
