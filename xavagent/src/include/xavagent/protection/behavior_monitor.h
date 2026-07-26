#pragma once

#include <linux/fanotify.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <outcome.hpp>
#include <outcome/config.hpp>
#include <outcome/result.hpp>
#include <unordered_map>
#include <unordered_set>

#include "xavagent/protection/event.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavagent {
class IEventListener;

class IEventProvider {
public:
    virtual ~IEventProvider() = default;

public:
    // These two function shouldn't block the caller.
    virtual outcome::result<void> start() = 0;
    virtual outcome::result<void> stop() = 0;

    virtual std::uint64_t lost_event_count() = 0;
    virtual outcome::result<void> listener_register(
        std::shared_ptr<IEventListener> listener) = 0;
    virtual outcome::result<void> listener_unregister(
        std::shared_ptr<IEventListener> listener) = 0;
};

class IEventListener {
public:
    virtual ~IEventListener() = default;

public:
    // Procedure: accept? -> enqueue -> on_event.
    virtual bool is_accept(const Event& event) = 0;
    virtual outcome::result<void> accept(const Event& event) = 0;
};

class BehaviorMonitorManager {
public:
    BehaviorMonitorManager();
    ~BehaviorMonitorManager();
    BehaviorMonitorManager(const BehaviorMonitorManager&) = delete;
    BehaviorMonitorManager& operator=(const BehaviorMonitorManager&) = delete;
    BehaviorMonitorManager(BehaviorMonitorManager&&) = delete;
    BehaviorMonitorManager& operator=(BehaviorMonitorManager&&) = delete;

public:
    void add_behavior_monitor(std::shared_ptr<IEventProvider> monitor);

public:
    void start_monitoring();
    void stop_monitoring();

public:
    std::uint64_t total_event_count() const { return this->total_event_count_; }

    std::uint64_t suspicious_event_count() const {
        return this->suspicious_event_count_;
    }

private:
    std::unordered_map<Process, std::deque<Event>> procs_events_;
    std::atomic_uint64_t total_event_count_;
    std::atomic_uint64_t suspicious_event_count_;
    std::unordered_set<std::shared_ptr<IEventProvider>> behavior_monitors_;
};
}  // namespace xavagent
