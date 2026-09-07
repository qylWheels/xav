#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/stdio_over_socket_rule.h"

#include <sys/syscall.h>

#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
StdioOverSocketRule::StdioOverSocketRule() = default;

StdioOverSocketRule::~StdioOverSocketRule() = default;

std::string StdioOverSocketRule::name() { return "stdio_over_socket_rule"; }

std::string StdioOverSocketRule::description() {
    return "A rule to detect standard input/output over socket (reverse "
           "shell)";
}

outcome::result<std::uint8_t> StdioOverSocketRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t StdioOverSocketRule::event_seq_size_hint() { return 1; }

outcome::result<void> StdioOverSocketRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        const Process& process = syscall_event.process;
        auto& proc_socket_fds = this->proc_socket_fds_[process];
        auto& fsm = this->proc_fsms_[process];

        const bool socket_open =
            fsm.is(sml::state<StdioOverSocketRuleFSM::SocketOpened>);

        switch (syscall_event.id) {
            case SYS_socket:
            case SYS_socketpair:
            case SYS_accept:
            case SYS_accept4: {
                // The newly created socket file descriptor is returned.
                const auto fd = static_cast<std::int64_t>(syscall_event.ret);
                if (fd >= 0) {
                    proc_socket_fds.insert(fd);
                    fsm.process_event(StdioOverSocketRuleFSM::SocketOpen{});
                }
                break;
            }
            case SYS_dup: {
                // dup(oldfd) duplicates onto the lowest available fd, which is
                // returned by ret. A duplicate of a socket is still a socket.
                const auto oldfd =
                    static_cast<std::int64_t>(syscall_event.args[0]);
                if (proc_socket_fds.count(oldfd) != 0 &&
                    static_cast<std::int64_t>(syscall_event.ret) >= 0) {
                    proc_socket_fds.insert(
                        static_cast<std::int64_t>(syscall_event.ret));
                }
                break;
            }
            case SYS_dup2:
            case SYS_dup3: {
                const auto oldfd =
                    static_cast<std::int64_t>(syscall_event.args[0]);
                const auto newfd =
                    static_cast<std::int64_t>(syscall_event.args[1]);

                if (proc_socket_fds.count(oldfd) == 0) {
                    break;
                }
                // The duplicate lands on a non-standard fd: still a socket,
                // no redirection of stdio yet.
                if (newfd > 2) {
                    proc_socket_fds.insert(newfd);
                    break;
                }

                // The socket was duplicated onto one of the standard I/O
                // descriptors (0, 1 or 2). Feed the FSM and only report the
                // actual SocketOpen -> StdioBound transition, which happens
                // once per socket (the FSM stays in StdioBound until a new
                // socket rearms it).
                if (socket_open) {
                    fsm.process_event(StdioOverSocketRuleFSM::DupToStdio{});
                    if (fsm.is(
                            sml::state<StdioOverSocketRuleFSM::StdioBounded>)) {
                        for (auto cb : this->callbacks_on_warning_) {
                            auto info = StdioOverSocketRuleWarningInfo(
                                process, static_cast<std::uint8_t>(newfd),
                                static_cast<std::uint64_t>(oldfd));
                            (*cb)(info);
                        }
                    }
                }
                break;
            }
            case SYS_close: {
                proc_socket_fds.erase(
                    static_cast<std::int64_t>(syscall_event.args[0]));
                break;
            }
            default: {
                // Ignore.
                break;
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> StdioOverSocketRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> StdioOverSocketRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
