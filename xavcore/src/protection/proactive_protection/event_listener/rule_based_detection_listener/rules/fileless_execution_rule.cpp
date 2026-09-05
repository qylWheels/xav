#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/fileless_execution_rule.h"

#include <sys/syscall.h>

#include <boost/sml.hpp>
#include <format>
#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
FilelessExecutionRule::FilelessExecutionRule() = default;

FilelessExecutionRule::~FilelessExecutionRule() = default;

std::string FilelessExecutionRule::name() { return "fileless_execution_rule"; }

std::string FilelessExecutionRule::description() {
    return "A rule to detect fileless execution";
}

outcome::result<std::uint8_t> FilelessExecutionRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t FilelessExecutionRule::event_seq_size_hint() { return 20; }

outcome::result<void> FilelessExecutionRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id == SYS_memfd_create) {
            this->fsm_.process_event(FilelessExecutionRuleFSM::CreateMemFd{});
            this->memfd_fd_ = syscall_event.ret;
        } else if ((syscall_event.id == SYS_execve ||
                    syscall_event.id == SYS_execveat) &&
                   this->fsm_.is(sml::state<
                                 FilelessExecutionRuleFSM::MemFdCreated>)) {
            auto a_data = std::get<ExecveSyscallAdditionalData>(
                syscall_event.additional_data);
            if (!a_data.path.has_value()) {
                return outcome::success();
            }

            std::regex re(
                std::format(".*/proc/self/fd/{}.*", this->memfd_fd_));
            if (std::regex_match(a_data.path.value(), re)) {
                this->fsm_.process_event(FilelessExecutionRuleFSM::Execve{});

                // Report a warning and renew the FSM for the next sequence.
                for (auto cb : this->callbacks_on_warning_) {
                    auto info =
                        FilelessExecutionRuleWarningInfo(a_data.path.value());
                    (*cb)(info);
                }
                this->fsm_ = sml::sm<FilelessExecutionRuleFSM>();
                this->memfd_fd_ = -1;
            }
        } else {
            // Void.
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> FilelessExecutionRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> FilelessExecutionRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
