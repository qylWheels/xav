#include "xavagent/protection/behavior_monitor.h"

namespace xavagent {
BehaviorMonitorManager::BehaviorMonitorManager()
    : total_event_count_(0), suspicious_event_count_(0) {}

BehaviorMonitorManager::~BehaviorMonitorManager() {}

void BehaviorMonitorManager::add_behavior_monitor(
    std::shared_ptr<IBehaviorMonitor> monitor) {
    this->behavior_monitors_.push_back(monitor);
}

// FIXME: monitor->start_monitoring() might block the caller.
void BehaviorMonitorManager::start_monitoring() {
    for (auto& monitor : this->behavior_monitors_) {
        monitor->start_monitoring();
    }
}

void BehaviorMonitorManager::stop_monitoring() {
    for (auto& monitor : this->behavior_monitors_) {
        monitor->stop_monitoring();
    }
}
}  // namespace xavagent
