#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/process_vm_inject_rule.h"

#include <sys/syscall.h>

#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
ProcessVmInjectRule::ProcessVmInjectRule() = default;

ProcessVmInjectRule::~ProcessVmInjectRule() = default;

std::string ProcessVmInjectRule::name() { return "process_vm_inject_rule"; }

std::string ProcessVmInjectRule::description() {
    return "A rule to detect process VM injection";
}

outcome::result<std::uint8_t> ProcessVmInjectRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t ProcessVmInjectRule::event_seq_size_hint() { return 1; }

outcome::result<void> ProcessVmInjectRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id == SYS_process_vm_writev) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info = ProcessVmInjectRuleWarningInfo{};
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> ProcessVmInjectRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> ProcessVmInjectRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
