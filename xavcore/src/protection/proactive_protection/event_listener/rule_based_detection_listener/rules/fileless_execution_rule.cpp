#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/fileless_execution_rule.h"

#include <sys/syscall.h>

#include <boost/sml.hpp>
#include <regex>

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
    // Reset FSM. i.e. renew it.
    this->fsm_ = sml::sm<FilelessExecutionRuleFSM>();
    int fd = -1;

    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());
            if (syscall_event.id == SYS_memfd_create) {
                this->fsm_.process_event(
                    FilelessExecutionRuleFSM::CreateMemFd{});
                fd = syscall_event.ret;
            } else if ((syscall_event.id == SYS_execve ||
                        syscall_event.id == SYS_execveat) &&
                       this->fsm_.is(sml::state<
                                     FilelessExecutionRuleFSM::MemFdCreated>)) {
                auto a_data = std::get<ExecveSyscallAdditionalData>(
                    syscall_event.additional_data);
                if (!a_data.path.has_value()) {
                    continue;
                }

                std::regex re(std::format(".*/proc/self/fd/{}.*", fd));
                if (std::regex_match(a_data.path.value(), re)) {
                    this->fsm_.process_event(
                        FilelessExecutionRuleFSM::Execve{});
                }
            } else {
                // Void.
            }
        } catch (...) {
            continue;
        }
    }

    std::uint8_t severity = 0;
    if (this->fsm_.is(sml::state<FilelessExecutionRuleFSM::Execved>)) {
        severity = 80;
    }
    return severity;
}

std::size_t FilelessExecutionRule::event_seq_size_hint() { return 20; }
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
