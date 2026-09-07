#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/ptrace_code_injection_rule.h"

#include <sys/ptrace.h>
#include <sys/syscall.h>

#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
PtraceCodeInjectionRule::PtraceCodeInjectionRule() = default;

PtraceCodeInjectionRule::~PtraceCodeInjectionRule() = default;

std::string PtraceCodeInjectionRule::name() {
    return "ptrace_code_injection_rule";
}

std::string PtraceCodeInjectionRule::description() {
    return "A rule to detect ptrace-based code injection";
}

outcome::result<std::uint8_t> PtraceCodeInjectionRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t PtraceCodeInjectionRule::event_seq_size_hint() { return 1; }

outcome::result<void> PtraceCodeInjectionRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id != SYS_ptrace) {
            return outcome::success();
        }

        const auto request = syscall_event.args[0];
        if (request != PTRACE_POKETEXT && request != PTRACE_POKEDATA) {
            return outcome::success();
        }

        for (auto cb : this->callbacks_on_warning_) {
            auto info = PtraceCodeInjectionRuleWarningInfo(
                syscall_event.process, syscall_event.args[1], request);
            (*cb)(info);
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> PtraceCodeInjectionRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> PtraceCodeInjectionRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
