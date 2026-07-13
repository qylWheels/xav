#pragma once

#include "xavagent/edr/behavioral_protection/behavior_monitor.h"
#include "xavagent/edr/on_access_scanner.h"

namespace xavagent {
class GlobalContext {
public:
    static GlobalContext& get_global_context() {
        static GlobalContext instance;
        return instance;
    }

    OnAccessScanner& on_access_scanner() { return this->on_access_scanner_; }

    BehaviorMonitor& behavior_monitor() { return this->behavior_monitor_; }

private:
    GlobalContext();
    ~GlobalContext();
    GlobalContext(const GlobalContext&) = delete;
    GlobalContext& operator=(const GlobalContext&) = delete;
    GlobalContext(GlobalContext&&) = delete;
    GlobalContext& operator=(GlobalContext&&) = delete;

private:
    OnAccessScanner on_access_scanner_;
    BehaviorMonitor behavior_monitor_;
};
}  // namespace xavagent
