#pragma once

#include "xavcore/protection/proactive_protection/behavior_monitor.h"

namespace xavcore {
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
