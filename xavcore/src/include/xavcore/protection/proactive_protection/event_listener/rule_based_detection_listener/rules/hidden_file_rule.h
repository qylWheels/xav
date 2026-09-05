#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
struct HiddenFileRuleWarningInfo : public IRuleWarningInfo {
    HiddenFileRuleWarningInfo(std::string path) : path(path) {}

    virtual std::uint8_t severity() const override { return 30; }

    std::string path;
};

class HiddenFileRule : public IRuleBasedDetectionListenerRule {
public:
    HiddenFileRule();
    ~HiddenFileRule();
    HiddenFileRule(const HiddenFileRule&) = delete;
    HiddenFileRule& operator=(const HiddenFileRule&) = delete;
    HiddenFileRule(HiddenFileRule&&) = delete;
    HiddenFileRule& operator=(HiddenFileRule&&) = delete;

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
    std::unordered_set<std::function<void(const IRuleWarningInfo&)>*>
        callbacks_on_warning_;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
