#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/kernel_module_loading_rule.h"

#include <sys/syscall.h>

#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
KernelModuleLoadingRule::KernelModuleLoadingRule() = default;

KernelModuleLoadingRule::~KernelModuleLoadingRule() = default;

std::string KernelModuleLoadingRule::name() {
    return "kernel_module_loading_rule";
}

std::string KernelModuleLoadingRule::description() {
    return "A rule to detect kernel module loading";
}

outcome::result<std::uint8_t> KernelModuleLoadingRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t KernelModuleLoadingRule::event_seq_size_hint() { return 1; }

outcome::result<void> KernelModuleLoadingRule::push_event(
    const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id == SYS_init_module ||
            syscall_event.id == SYS_finit_module) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info = KernelModuleLoadingRuleWarningInfo{};
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> KernelModuleLoadingRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> KernelModuleLoadingRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
