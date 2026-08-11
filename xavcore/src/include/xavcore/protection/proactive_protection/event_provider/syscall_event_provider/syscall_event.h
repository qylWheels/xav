#pragma once

#include <chrono>
#include <vector>

#include "xavcore/protection/proactive_protection/event.h"

namespace xavcore {
struct SyscallEvent : public IEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    Process process;
    std::uint32_t id;
    std::vector<std::uint64_t> args;
    std::uint64_t ret;
};
}  // namespace xavcore
