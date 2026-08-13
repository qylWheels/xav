#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/anti_debug_rule.h"

#include <sys/ptrace.h>
#include <sys/syscall.h>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
AntiDebugRule::AntiDebugRule() = default;

AntiDebugRule::~AntiDebugRule() = default;

std::string AntiDebugRule::name() { return "anti_debug_rule"; }

std::string AntiDebugRule::description() {
    return "A rule to detect anti-debugging techniques";
}

outcome::result<std::uint8_t> AntiDebugRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());
            if (syscall_event.id == SYS_ptrace &&
                syscall_event.args[0] == PTRACE_TRACEME) {
                return 70;
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t AntiDebugRule::event_seq_size_hint() { return 1; }

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
