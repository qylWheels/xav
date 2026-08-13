#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_based_detection_listener.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstddef>
#include <vector>

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

    // Apply rules.
    for (auto& rule : this->rules_) {
        const auto& proc_syscall_events =
            this->proc_syscall_events_[syscall_event.process];
        std::size_t n =
            std::min(rule->event_seq_size_hint(), proc_syscall_events.size());
        std::vector<SyscallEvent> event_slice(proc_syscall_events.end() - n,
                                              proc_syscall_events.end());
        std::vector<std::reference_wrapper<IEvent>> event_ref_slice(
            event_slice.begin(), event_slice.end());
        auto severity = rule->apply(event_ref_slice);
        if (severity.has_error()) {
            this->logger_->error("Error when apply rule");
        } else {
            if (severity.value() > 20) {
                this->logger_->info(
                    "Event sequence severity of {}: {} (Rule {}, Description: "
                    "{})",
                    syscall_event.process.pid, severity.value(), rule->name(),
                    rule->description());
                this->logger_->info("Event count of {}: {}\n",
                                    syscall_event.process.pid,
                                    proc_syscall_events.size());
            }
        }
    }

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
