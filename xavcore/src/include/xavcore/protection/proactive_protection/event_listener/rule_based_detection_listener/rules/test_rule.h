#pragma once

#include <boost/sml.hpp>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace xavcore {
namespace proactive_protection_rule {
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
    struct FSM {
        // States.
        struct Start {};
        struct Rename1 {};
        struct Rename2 {};
        struct Rename3 {};
        struct End {};

        // Events.
        struct Rename {};

        auto operator()() const {
            return boost::sml::make_transition_table(
                *Start + event<Rename> = Rename1,
                Rename1 + event<Rename> = Rename2,
                Rename2 + event<Rename> = Rename3,
                Rename3 + event<Rename> = End, End + event<Rename> = End);
        }
    };
};
}  // namespace proactive_protection_rule
}  // namespace xavcore
