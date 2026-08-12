#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_based_detection_listener.h"

#include <spdlog/spdlog.h>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
RuleBasedDetectionListener::RuleBasedDetectionListener(spdlog::logger& logger)
    : logger_(&logger) {}

RuleBasedDetectionListener::~RuleBasedDetectionListener() = default;

bool RuleBasedDetectionListener::is_accept(const IEvent& event) {
    try {
        (void)dynamic_cast<const SyscallEvent&>(event);
        return true;
    } catch (...) {
        return false;
    }
}

outcome::result<void> RuleBasedDetectionListener::accept(const IEvent& event) {
    const SyscallEvent& syscall_event =
        dynamic_cast<const SyscallEvent&>(event);
    this->proc_syscall_events_[syscall_event.process].push_back(syscall_event);
    return outcome::success();
}

outcome::result<void> RuleBasedDetectionListener::add_rule(
    IProactiveProtectionRule& rule) {
    this->rules_.insert(&rule);
    return outcome::success();
}

outcome::result<void> RuleBasedDetectionListener::remove_rule(
    IProactiveProtectionRule& rule) {
    this->rules_.erase(&rule);
    return outcome::success();
}

}  // namespace xavcore
