#pragma once

#include <boost/sml.hpp>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace sml = boost::sml;

namespace xavcore {
namespace proactive_protection_rule {

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
    virtual outcome::result<std::uint8_t> apply(
        std::span<std::reference_wrapper<IEvent>> event_seq) override;

private:
    sml::sm<TestRuleFSM> fsm_;
};
}  // namespace proactive_protection_rule
}  // namespace xavcore
