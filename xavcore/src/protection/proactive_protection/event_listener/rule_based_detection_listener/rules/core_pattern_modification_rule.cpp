#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/core_pattern_modification_rule.h"

#include <sys/syscall.h>

#include <iostream>
#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
CorePatternModificationRule::CorePatternModificationRule() = default;

CorePatternModificationRule::~CorePatternModificationRule() = default;

std::string CorePatternModificationRule::name() {
    return "core_pattern_modification_rule";
}

std::string CorePatternModificationRule::description() {
    return "A rule to detect core pattern modification";
}

outcome::result<std::uint8_t> CorePatternModificationRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t CorePatternModificationRule::event_seq_size_hint() { return 1; }

outcome::result<void> CorePatternModificationRule::push_event(
    const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        std::cout << "!";
        if (syscall_event.id == SYS_write) {
            auto path = std::get<WriteSyscallAdditionalData>(
                            syscall_event.additional_data)
                            .fd_path.value();
            std::regex re("/proc/sys/kernel/core_pattern");
            if (std::regex_search(path, re)) {
                for (auto cb : this->callbacks_on_warning_) {
                    auto info = CorePatternModificationRuleWarningInfo(path);
                    (*cb)(info);
                }
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> CorePatternModificationRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> CorePatternModificationRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore