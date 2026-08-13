#pragma once

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

class TestRule : public IProactiveProtectionRule {
public:
    TestRule();
    ~TestRule();
    TestRule(const TestRule&) = delete;
    TestRule& operator=(const TestRule&) = delete;
    TestRule(TestRule&&) = delete;
    TestRule& operator=(TestRule&&) = delete;

public:
    virtual std::string name() override;
    virtual std::string description() override;
    virtual outcome::result<std::uint8_t> apply(
        std::span<std::reference_wrapper<IEvent>> event_seq) override;
    virtual std::size_t event_seq_size_hint() override;

private:
    sml::sm<TestRuleFSM> fsm_;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
