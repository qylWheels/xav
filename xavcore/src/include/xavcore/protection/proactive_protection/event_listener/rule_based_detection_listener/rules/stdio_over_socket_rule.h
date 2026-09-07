#pragma once

#include <boost/sml.hpp>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace sml = boost::sml;

namespace xavcore {
namespace rule_based_detection_listener_rules {
// FSM describing the reverse-shell (stdio-over-socket) pattern for one
// process: a socket must first be created, then duplicated onto one of the
// standard I/O descriptors (0, 1 or 2).
struct StdioOverSocketRuleFSM {
    // States.
    struct Start {};
    struct SocketOpened {};
    struct StdioBounded {};

    // Events.
    struct SocketOpen {};
    struct DupToStdio {};

    auto operator()() const {
        return sml::make_transition_table(
            *sml::state<Start> + sml::event<SocketOpen> =
                sml::state<SocketOpened>,
            sml::state<SocketOpened> + sml::event<DupToStdio> =
                sml::state<StdioBounded>,
            // A newly created socket rearms the FSM for the next attempt.
            sml::state<StdioBounded> + sml::event<SocketOpen> =
                sml::state<SocketOpened>);
    }
};

struct StdioOverSocketRuleWarningInfo : public IRuleWarningInfo {
    StdioOverSocketRuleWarningInfo(Process process, std::uint8_t stdio_fd,
                                   std::uint64_t socket_fd)
        : process_(process), stdio_fd(stdio_fd), socket_fd(socket_fd) {}

    virtual std::uint8_t severity() const override { return 90; }
    virtual Process process() const override { return this->process_; }
    virtual std::shared_ptr<IRuleWarningInfo> clone() const override {
        return std::make_shared<StdioOverSocketRuleWarningInfo>(*this);
    }

    // The standard I/O file descriptor that was redirected (0=stdin,
    // 1=stdout, 2=stderr).
    std::uint8_t stdio_fd;
    // The socket file descriptor that was duplicated onto the standard stream.
    std::uint64_t socket_fd;

private:
    Process process_;
};

class StdioOverSocketRule : public IRuleBasedDetectionListenerRule {
public:
    StdioOverSocketRule();
    ~StdioOverSocketRule();
    StdioOverSocketRule(const StdioOverSocketRule&) = delete;
    StdioOverSocketRule& operator=(const StdioOverSocketRule&) = delete;
    StdioOverSocketRule(StdioOverSocketRule&&) = delete;
    StdioOverSocketRule& operator=(StdioOverSocketRule&&) = delete;

public:  // IRuleBasedDetectionListenerRule methods.
    virtual std::string name() override;
    virtual std::string description() override;
    virtual outcome::result<std::uint8_t> apply(
        std::span<std::reference_wrapper<IEvent>> event_seq) override;
    virtual std::size_t event_seq_size_hint() override;
    virtual outcome::result<void> push_event(const IEvent& event) override;
    virtual outcome::result<void> register_warning_callback(
        std::function<void(const IRuleWarningInfo&)>& cb) override;
    virtual outcome::result<void> unregister_warning_callback(
        std::function<void(const IRuleWarningInfo&)>& cb) override;

private:
    // Per-process FSM tracking the socket-to-stdio-redirection sequence.
    std::unordered_map<Process, sml::sm<StdioOverSocketRuleFSM>> proc_fsms_;
    // Per-process set of file descriptors known to be sockets, so that a
    // dup2()/dup3() onto 0/1/2 only fires for a genuine socket source.
    std::unordered_map<Process, std::unordered_set<std::int64_t>>
        proc_socket_fds_;
    std::unordered_set<std::function<void(const IRuleWarningInfo&)>*>
        callbacks_on_warning_;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
