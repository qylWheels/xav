#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "xavcore/protection/proactive_protection/event.h"

namespace xavcore {
struct ReadSyscallAdditionalData {
    std::optional<std::string> fd_path;
};

struct WriteSyscallAdditionalData {
    std::optional<std::string> fd_path;
};

struct OpenSyscallAdditionalData {
    std::optional<std::string> path;
};

struct OpenatSyscallAdditionalData {
    std::optional<std::string> path;
};

struct Openat2SyscallAdditionalData {
    std::optional<std::string> path;
};

struct CloseSyscallAdditionalData {
    std::optional<std::string> fd_path;
};

struct CreatSyscallAdditionalData {
    std::optional<std::string> path;
};

struct UnlinkSyscallAdditionalData {
    std::optional<std::string> path;
};

// Normal syscall event, for those who don't need to parse arguments.
struct SyscallEvent : public IEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    Process process;
    std::uint32_t id;
    std::vector<std::uint64_t> args;
    std::uint64_t ret;

    // Additional data.
    std::variant<std::monostate, ReadSyscallAdditionalData,
                 WriteSyscallAdditionalData, OpenSyscallAdditionalData,
                 OpenatSyscallAdditionalData, Openat2SyscallAdditionalData,
                 CloseSyscallAdditionalData, CreatSyscallAdditionalData,
                 UnlinkSyscallAdditionalData>
        additional_data;
};
}  // namespace xavcore
