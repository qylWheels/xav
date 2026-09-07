#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/system_request_key_mod_rule.h"

#include <sys/syscall.h>

#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
SystemRequestKeyModRule::SystemRequestKeyModRule() = default;

SystemRequestKeyModRule::~SystemRequestKeyModRule() = default;

std::string SystemRequestKeyModRule::name() {
    return "system_request_key_mod_rule";
}

std::string SystemRequestKeyModRule::description() {
    return "A rule to detect modifications to System Request Key (SysRq) "
           "configuration";
}

outcome::result<std::uint8_t> SystemRequestKeyModRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t SystemRequestKeyModRule::event_seq_size_hint() { return 1; }

outcome::result<void> SystemRequestKeyModRule::push_event(
    const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id != SYS_write) {
            return outcome::success();
        }

        // /proc/sys/kernel/sysrq (enable/disable) and /proc/sysrq-trigger
        // (direct kernel commands) are the SysRq configuration entry points.
        static const std::regex sysrq_re(
            "(/proc/sys/kernel/sysrq|/proc/sysrq-trigger)");
        const std::string path = std::get<WriteSyscallAdditionalData>(
                                     syscall_event.additional_data)
                                     .fd_path.value();
        if (std::regex_search(path, sysrq_re)) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info = SystemRequestKeyModRuleWarningInfo(
                    syscall_event.process, path);
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> SystemRequestKeyModRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> SystemRequestKeyModRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
