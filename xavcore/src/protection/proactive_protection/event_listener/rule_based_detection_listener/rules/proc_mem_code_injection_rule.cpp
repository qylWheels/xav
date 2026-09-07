#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/proc_mem_code_injection_rule.h"

#include <sys/syscall.h>

#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
ProcMemCodeInjectionRule::ProcMemCodeInjectionRule() = default;

ProcMemCodeInjectionRule::~ProcMemCodeInjectionRule() = default;

std::string ProcMemCodeInjectionRule::name() {
    return "proc_mem_code_injection_rule";
}

std::string ProcMemCodeInjectionRule::description() {
    return "A rule to detect code injection via /proc/[pid]/mem write";
}

outcome::result<std::uint8_t> ProcMemCodeInjectionRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t ProcMemCodeInjectionRule::event_seq_size_hint() { return 1; }

outcome::result<void> ProcMemCodeInjectionRule::push_event(
    const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id == SYS_write) {
            std::string path = std::get<WriteSyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .fd_path.value();
            std::regex re("/proc/\\d+/mem");
            if (std::regex_search(path, re)) {
                for (auto cb : this->callbacks_on_warning_) {
                    auto info = ProcMemCodeInjectionRuleWarningInfo(
                        syscall_event.process, path);
                    (*cb)(info);
                }
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> ProcMemCodeInjectionRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> ProcMemCodeInjectionRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
