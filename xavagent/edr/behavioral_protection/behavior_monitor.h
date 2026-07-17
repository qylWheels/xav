#pragma once

#include <linux/fanotify.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

#include "edr/behavioral_protection/event.h"

namespace xavagent {
class IBehaviorMonitor {
public:
    virtual ~IBehaviorMonitor() = default;

public:
    virtual void start_monitoring() = 0;
    virtual void stop_monitoring() = 0;
    virtual std::span<Event> all_events() const = 0;
    virtual std::size_t event_count() const = 0;
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
    void add_behavior_monitor(std::shared_ptr<IBehaviorMonitor> monitor);

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
    std::vector<std::shared_ptr<IBehaviorMonitor>> behavior_monitors_;
};
}  // namespace xavagent
