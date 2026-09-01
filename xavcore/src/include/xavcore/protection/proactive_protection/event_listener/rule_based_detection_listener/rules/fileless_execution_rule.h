#pragma once

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

private:
    sml::sm<FilelessExecutionRuleFSM> fsm_;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
