#pragma once

#include <unordered_set>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
struct AntiDebugRuleWarningInfo : public IRuleWarningInfo {
    virtual inline std::uint8_t severity() override { return 40; }
};

class AntiDebugRule : public IRuleBasedDetectionListenerRule {
public:
    AntiDebugRule();
    ~AntiDebugRule();
    AntiDebugRule(const AntiDebugRule&) = delete;
    AntiDebugRule& operator=(const AntiDebugRule&) = delete;
    AntiDebugRule(AntiDebugRule&&) = delete;
    AntiDebugRule& operator=(AntiDebugRule&&) = delete;

public:  // IRuleBasedDetectionListenerRule methods.
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
    // Callbacks on warning.
    std::unordered_set<std::function<void(IRuleWarningInfo&)>*> cbs_on_warning_;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
