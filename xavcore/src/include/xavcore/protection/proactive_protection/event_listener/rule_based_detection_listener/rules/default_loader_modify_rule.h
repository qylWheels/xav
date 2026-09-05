#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_set>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
struct DefaultLoaderModifyRuleWarningInfo : public IRuleWarningInfo {
    DefaultLoaderModifyRuleWarningInfo(std::string path) : path(path) {}

    virtual std::uint8_t severity() const override { return 70; }

    std::string path;
};

class DefaultLoaderModifyRule : public IRuleBasedDetectionListenerRule {
public:
    DefaultLoaderModifyRule();
    ~DefaultLoaderModifyRule();
    DefaultLoaderModifyRule(const DefaultLoaderModifyRule&) = delete;
    DefaultLoaderModifyRule& operator=(const DefaultLoaderModifyRule&) = delete;
    DefaultLoaderModifyRule(DefaultLoaderModifyRule&&) = delete;
    DefaultLoaderModifyRule& operator=(DefaultLoaderModifyRule&&) = delete;

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
    std::unordered_set<std::function<void(const IRuleWarningInfo&)>*> cbs_;
};
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
