#pragma once

#include <spdlog/logger.h>

#include <cstddef>
#include <deque>
#include <unordered_map>
#include <unordered_set>

#include "xavcore/protection/proactive_protection/behavior_monitor.h"
#include "xavcore/protection/proactive_protection/event.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
class RuleBasedDetectionListener : public IEventListener {
public:
    RuleBasedDetectionListener(spdlog::logger& logger);
    ~RuleBasedDetectionListener();
    RuleBasedDetectionListener(const RuleBasedDetectionListener&) = delete;
    RuleBasedDetectionListener& operator=(const RuleBasedDetectionListener&) =
        delete;
    RuleBasedDetectionListener(RuleBasedDetectionListener&&) = delete;
    RuleBasedDetectionListener& operator=(RuleBasedDetectionListener&&) =
        delete;

public:  // IEventListener interface methods.
    virtual bool is_accept(const IEvent& event) override;
    virtual outcome::result<void> accept(const IEvent& event) override;

public:
    outcome::result<void> add_rule(IRuleBasedDetectionListenerRule& rule);
    outcome::result<void> remove_rule(IRuleBasedDetectionListenerRule& rule);

private:
    spdlog::logger* logger_;
    std::unordered_set<IRuleBasedDetectionListenerRule*> rules_;
    std::unordered_map<Process, std::deque<SyscallEvent>> proc_syscall_events_;

    // The max size hint of the event sequence returned by all the rules.
    std::size_t max_size_hint_;
};
}  // namespace xavcore
