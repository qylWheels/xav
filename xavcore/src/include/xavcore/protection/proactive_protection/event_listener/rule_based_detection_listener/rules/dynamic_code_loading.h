#pragma once

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
class DynamicCodeLoadingRule : public IRuleBasedDetectionListenerRule {
public:
    DynamicCodeLoadingRule();
    ~DynamicCodeLoadingRule();
    DynamicCodeLoadingRule(const DynamicCodeLoadingRule&) = delete;
    DynamicCodeLoadingRule& operator=(const DynamicCodeLoadingRule&) = delete;
    DynamicCodeLoadingRule(DynamicCodeLoadingRule&&) = delete;
    DynamicCodeLoadingRule& operator=(DynamicCodeLoadingRule&&) = delete;

public:  // IRuleBasedDetectionListenerRule methods.
    virtual std::string name() override;
    virtual std::string description() override;
    virtual outcome::result<std::uint8_t> apply(
        std::span<std::reference_wrapper<IEvent>> event_seq) override;
    virtual std::size_t event_seq_size_hint() override;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
