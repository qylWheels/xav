#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/test_rule.h"

#include <sys/syscall.h>

#include <boost/sml.hpp>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace proactive_protection_rule {
TestRule::TestRule() = default;

TestRule::~TestRule() = default;

outcome::result<std::uint8_t> TestRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());
            if (syscall_event.id == SYS_process_vm_writev) {
                this->fsm_.process_event(TestRuleFSM::ProcessVmWriteEvent{});
            }
        } catch (...) {
            continue;
        }
    }

    std::uint8_t severity = 0;
    if (this->fsm_.is(sml::state<TestRuleFSM::ProcessVmWrite1>)) {
        severity = 50;
    } else if (this->fsm_.is(sml::state<TestRuleFSM::ProcessVmWrite2>)) {
        severity = 80;
    } else if (this->fsm_.is(sml::X)) {
        severity = 90;
    } else {
        severity = 0;
    }
    return severity;
}
}  // namespace proactive_protection_rule
}  // namespace xavcore
