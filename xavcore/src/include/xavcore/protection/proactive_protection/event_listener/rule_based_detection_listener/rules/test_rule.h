#pragma once

#include <cstdint>
#include <unordered_set>

#include <boost/sml.hpp>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace sml = boost::sml;

namespace xavcore {
namespace rule_based_detection_listener_rules {
// FSM.
struct TestRuleFSM {
    // States.
    struct Start {};
    struct ProcessVmWrite1 {};
    struct ProcessVmWrite2 {};

    // Events.
    struct ProcessVmWriteEvent {};

    auto operator()() const {
        return sml::make_transition_table(
            *sml::state<Start> + sml::event<ProcessVmWriteEvent> =
                sml::state<ProcessVmWrite1>,
            sml::state<ProcessVmWrite1> + sml::event<ProcessVmWriteEvent> =
                sml::state<ProcessVmWrite2>,
            sml::state<ProcessVmWrite2> + sml::event<ProcessVmWriteEvent> =
                sml::X);
    }
};

struct TestRuleWarningInfo : public IRuleWarningInfo {
    explicit TestRuleWarningInfo(std::uint8_t severity) : severity_(severity) {}

    virtual std::uint8_t severity() const override { return this->severity_; }

private:
    std::uint8_t severity_;
};

class TestRule : public IRuleBasedDetectionListenerRule {
public:
    TestRule();
    ~TestRule();
    TestRule(const TestRule&) = delete;
    TestRule& operator=(const TestRule&) = delete;
    TestRule(TestRule&&) = delete;
    TestRule& operator=(TestRule&&) = delete;

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
    sml::sm<TestRuleFSM> fsm_;
    std::unordered_set<std::function<void(const IRuleWarningInfo&)>*>
        callbacks_on_warning_;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
