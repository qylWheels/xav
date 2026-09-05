#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/dynamic_code_loading_rule.h"

#include <sys/mman.h>
#include <sys/syscall.h>

#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
DynamicCodeLoadingRule::DynamicCodeLoadingRule() = default;

DynamicCodeLoadingRule::~DynamicCodeLoadingRule() = default;

std::string DynamicCodeLoadingRule::name() {
    return "dynamic_code_loading_rule";
}

std::string DynamicCodeLoadingRule::description() {
    return "A rule to detect dynamic code loading";
}

outcome::result<std::uint8_t> DynamicCodeLoadingRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t DynamicCodeLoadingRule::event_seq_size_hint() { return 1; }

outcome::result<void> DynamicCodeLoadingRule::push_event(
    const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id == SYS_mprotect &&
            syscall_event.args[2] == (PROT_WRITE | PROT_EXEC)) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info = DynamicCodeLoadingRuleWarningInfo{};
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> DynamicCodeLoadingRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> DynamicCodeLoadingRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
