#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "xavcore/protection/proactive_protection/event.h"

namespace xavcore {
struct ReadSyscallAdditionalData {
    std::optional<std::string> fd_path;
};

// Normal syscall event, for those who don't need to parse arguments.
struct SyscallEvent : public IEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    Process process;
    std::uint32_t id;
    std::vector<std::uint64_t> args;
    std::uint64_t ret;

    // Additional data.
    std::variant<std::monostate, ReadSyscallAdditionalData> additional_data;
};
}  // namespace xavcore
