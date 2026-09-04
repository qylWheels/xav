#pragma once

#include <functional>
#include <unordered_set>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
struct CgroupReleaseAgentRuleWarningInfo : public IRuleWarningInfo {
    CgroupReleaseAgentRuleWarningInfo(const std::string& path) : path(path) {}

    virtual std::uint8_t severity() override { return 70; }

    std::string path;
};

class CgroupReleaseAgentRule : public IRuleBasedDetectionListenerRule {
public:
    CgroupReleaseAgentRule();
    ~CgroupReleaseAgentRule();
    CgroupReleaseAgentRule(const CgroupReleaseAgentRule&) = delete;
    CgroupReleaseAgentRule& operator=(const CgroupReleaseAgentRule&) = delete;
    CgroupReleaseAgentRule(CgroupReleaseAgentRule&&) = delete;
    CgroupReleaseAgentRule& operator=(CgroupReleaseAgentRule&&) = delete;

public:
    virtual std::string name() override;
    virtual std::string description() override;
    virtual outcome::result<std::uint8_t> apply(
        std::span<std::reference_wrapper<IEvent>> event_seq) override;
    virtual std::size_t event_seq_size_hint() override;
    virtual outcome::result<void> push_event(IEvent& event) override;
    virtual outcome::result<void> register_warning_callback(
        std::function<void(IRuleWarningInfo&)>& cb) override;
    virtual outcome::result<void> unregister_warning_callback(
        std::function<void(IRuleWarningInfo&)>& cb) override;

private:
    std::unordered_set<std::function<void(IRuleWarningInfo&)>*>
        callbacks_on_warning_;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
