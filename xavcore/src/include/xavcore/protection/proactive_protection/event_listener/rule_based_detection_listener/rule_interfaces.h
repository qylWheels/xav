#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <outcome/outcome.hpp>
#include <span>
#include <string>

#include "xavcore/protection/proactive_protection/event.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
class IRuleWarningInfo {
public:
    virtual ~IRuleWarningInfo() = default;

public:
    virtual std::uint8_t severity() = 0;
};

class IRuleBasedDetectionListenerRule {
public:
    virtual ~IRuleBasedDetectionListenerRule() = default;

public:
    virtual std::string name() = 0;

    virtual std::string description() = 0;

    // Return severity(0-100) of the event sequence.
    // The higher the severity, the more the event sequence is like a threat.
    [[deprecated]]
    virtual outcome::result<std::uint8_t> apply(
        std::span<std::reference_wrapper<IEvent>> event_seq) = 0;

    // Return the hint of the event sequence size.
    [[deprecated]]
    virtual std::size_t event_seq_size_hint() = 0;

    virtual outcome::result<void> push_event(IEvent& event) = 0;

    virtual outcome::result<void> register_warning_callback(
        std::function<void(IRuleWarningInfo&)>& cb) = 0;

    virtual outcome::result<void> unregister_warning_callback(
        std::function<void(IRuleWarningInfo&)>& cb) = 0;
};
}  // namespace xavcore
