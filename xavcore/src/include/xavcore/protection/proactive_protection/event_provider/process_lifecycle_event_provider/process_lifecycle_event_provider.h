#pragma once

#include <spdlog/logger.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cstdint>
#include <unordered_set>

#include "process_lifecycle_event_provider.skel.h"
#include "xavcore/protection/proactive_protection/behavior_monitor.h"

namespace xavcore {
struct ProcessCreateEvent : public IEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    std::uint32_t pid;
};

struct ProcessExitEvent : public IEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    std::uint32_t pid;
};

class ProcessLifecycleEventProvider : public IEventProvider {
public:
    ProcessLifecycleEventProvider(spdlog::logger& logger);
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

private:
    static int event_callback(void* ctx, void* data, std::size_t size);

private:
    enum class Status { Stopped, Running };

    Status status_;
    spdlog::logger* logger_;
    process_lifecycle_event_provider_bpf* skel_;
    ring_buffer* rb_;
    std::jthread monitor_thread_;
    std::atomic_uint64_t lost_event_count_;
    std::unordered_set<IEventListener*> listeners_;
};
}  // namespace xavcore
