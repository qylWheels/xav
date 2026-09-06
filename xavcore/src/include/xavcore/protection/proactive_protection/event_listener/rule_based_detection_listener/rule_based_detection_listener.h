#pragma once

#include <spdlog/logger.h>

#include <deque>
#include <functional>
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
    std::unordered_map<Process, std::deque<IRuleWarningInfo>>
        proc_violated_events_;
    std::function<void(const IRuleWarningInfo&)> callback_on_warning_;
};
}  // namespace xavcore
