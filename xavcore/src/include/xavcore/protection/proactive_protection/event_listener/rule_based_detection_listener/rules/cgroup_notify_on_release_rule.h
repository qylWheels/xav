#pragma once

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
class CgroupNotifyOnReleaseRule : public IRuleBasedDetectionListenerRule {
public:
    CgroupNotifyOnReleaseRule();
    ~CgroupNotifyOnReleaseRule();
    CgroupNotifyOnReleaseRule(const CgroupNotifyOnReleaseRule&) = delete;
    CgroupNotifyOnReleaseRule& operator=(const CgroupNotifyOnReleaseRule&) =
        delete;
    CgroupNotifyOnReleaseRule(CgroupNotifyOnReleaseRule&&) = delete;
    CgroupNotifyOnReleaseRule& operator=(CgroupNotifyOnReleaseRule&&) = delete;

public:
    virtual std::string name() override;
    virtual std::string description() override;
    virtual outcome::result<std::uint8_t> apply(
        std::span<std::reference_wrapper<IEvent>> event_seq) override;
    virtual std::size_t event_seq_size_hint() override;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
