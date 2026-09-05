#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/test_rule.h"

#include <sys/syscall.h>

#include <boost/sml.hpp>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
TestRule::TestRule() = default;

TestRule::~TestRule() = default;

std::string TestRule::name() { return "test_rule"; }

std::string TestRule::description() {
    return "A test rule to detect process_vm_writev syscall";
}

outcome::result<std::uint8_t> TestRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t TestRule::event_seq_size_hint() { return 5; }

outcome::result<void> TestRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id == SYS_process_vm_writev) {
            this->fsm_.process_event(TestRuleFSM::ProcessVmWriteEvent{});
        }
    } catch (...) {
        // Ignore.
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

    if (severity > 0) {
        for (auto cb : this->callbacks_on_warning_) {
            auto info = TestRuleWarningInfo(severity);
            (*cb)(info);
        }
    }

    // Renew the FSM once the terminal state is reached.
    if (this->fsm_.is(sml::X)) {
        this->fsm_ = sml::sm<TestRuleFSM>();
    }
    return outcome::success();
}

outcome::result<void> TestRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> TestRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
