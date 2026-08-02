#pragma once

#include <chrono>
#include <cstdint>

#include "xavcore/protection/proactive_protection/behavior_monitor.h"

namespace xavcore {
struct ProcessCreateEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    std::uint32_t pid;
};

struct ProcessExitEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    std::uint32_t pid;
};

class ProcessLifecycleEventProvider : public IEventProvider {
public:
    ProcessLifecycleEventProvider();
    ~ProcessLifecycleEventProvider();
    ProcessLifecycleEventProvider(const ProcessLifecycleEventProvider&) =
        delete;
    ProcessLifecycleEventProvider& operator=(
        const ProcessLifecycleEventProvider&) = delete;
    ProcessLifecycleEventProvider(ProcessLifecycleEventProvider&&) = delete;
    ProcessLifecycleEventProvider& operator=(ProcessLifecycleEventProvider&&) =
        delete;

public:
    virtual outcome::result<void> start() override;
    virtual outcome::result<void> stop() override;
    virtual std::uint64_t lost_event_count() override;
    virtual outcome::result<void> listener_register(
        IEventListener& listener) override;
    virtual outcome::result<void> listener_unregister(
        IEventListener& listener) override;
};
}  // namespace xavcore
