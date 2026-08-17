#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/core_pattern_modification_rule.h"

#include <sys/syscall.h>

#include <iostream>
#include <variant>

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
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());
            if (syscall_event.id == SYS_write &&
                std::holds_alternative<WriteSyscallAdditionalData>(
                    syscall_event.additional_data)) {
                auto additional_data = std::get<WriteSyscallAdditionalData>(
                    syscall_event.additional_data);
                if (additional_data.fd_path.has_value() &&
                    additional_data.fd_path.value() ==
                        "/proc/sys/kernel/core_pattern") {
                    std::cout << "Core pattern modification detected"
                              << std::endl;
                    return 60;
                }
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t CorePatternModificationRule::event_seq_size_hint() { return 1; }
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore