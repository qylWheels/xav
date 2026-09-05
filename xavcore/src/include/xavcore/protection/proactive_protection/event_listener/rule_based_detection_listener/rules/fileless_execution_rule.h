#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>

#include <boost/sml.hpp>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace sml = boost::sml;

namespace xavcore {
namespace rule_based_detection_listener_rules {
// FSM.
struct FilelessExecutionRuleFSM {
    // States.
    struct Start {};
    struct MemFdCreated {};
    struct Execved {};

    // Events.
    struct CreateMemFd {};
    struct Execve {};

    auto operator()() const {
        return sml::make_transition_table(
            *sml::state<Start> + sml::event<CreateMemFd> =
                sml::state<MemFdCreated>,
            sml::state<MemFdCreated> + sml::event<Execve> =
                sml::state<Execved>);
    }
};

struct FilelessExecutionRuleWarningInfo : public IRuleWarningInfo {
    FilelessExecutionRuleWarningInfo(std::string path) : path(path) {}

    virtual std::uint8_t severity() const override { return 80; }

    std::string path;
};

class FilelessExecutionRule : public IRuleBasedDetectionListenerRule {
public:
    FilelessExecutionRule();
    ~FilelessExecutionRule();
    FilelessExecutionRule(const FilelessExecutionRule&) = delete;
    FilelessExecutionRule& operator=(const FilelessExecutionRule&) = delete;
    FilelessExecutionRule(FilelessExecutionRule&&) = delete;
    FilelessExecutionRule& operator=(FilelessExecutionRule&&) = delete;

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
    int memfd_fd_ = -1;
    sml::sm<FilelessExecutionRuleFSM> fsm_;
    std::unordered_set<std::function<void(const IRuleWarningInfo&)>*>
        callbacks_on_warning_;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
