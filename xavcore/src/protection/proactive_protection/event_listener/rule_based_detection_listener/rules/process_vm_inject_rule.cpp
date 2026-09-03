#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/process_vm_inject_rule.h"

#include <sys/syscall.h>

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
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());

            if (syscall_event.id == SYS_process_vm_writev) {
                return 60;
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t ProcessVmInjectRule::event_seq_size_hint() { return 1; }
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
