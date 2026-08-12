#pragma once

#include <spdlog/logger.h>

#include <unordered_set>

#include "xavcore/protection/proactive_protection/behavior_monitor.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_interfaces.h"

namespace xavcore {
class RuleBasedDetectionListener : public IEventListener {
public:
    RuleBasedDetectionListener(spdlog::logger& logger);
    ~RuleBasedDetectionListener();
    RuleBasedDetectionListener(const RuleBasedDetectionListener&) = delete;
    RuleBasedDetectionListener& operator=(const RuleBasedDetectionListener&) =
        delete;
    RuleBasedDetectionListener(RuleBasedDetectionListener&&) = delete;
    RuleBasedDetectionListener& operator=(RuleBasedDetectionListener&&) =
        delete;

public:  // IEventListener interface methods.
    virtual bool is_accept(const IEvent& event) override;
    virtual outcome::result<void> accept(const IEvent& event) override;

public:
    outcome::result<void> add_rule(IProactiveProtectionRule& rule);
    outcome::result<void> remove_rule(IProactiveProtectionRule& rule);

private:
    spdlog::logger* logger_;
    std::unordered_set<IProactiveProtectionRule*> rules_;
};
}  // namespace xavcore
