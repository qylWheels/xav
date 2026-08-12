#pragma once

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
};
}  // namespace proactive_protection_rule
}  // namespace xavcore
