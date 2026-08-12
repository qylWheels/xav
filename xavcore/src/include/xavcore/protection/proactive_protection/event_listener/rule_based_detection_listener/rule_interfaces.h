#pragma once

#include <cstdint>
#include <functional>
#include <outcome/outcome.hpp>
#include <span>

#include "xavcore/protection/proactive_protection/event.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
class IProactiveProtectionRule {
public:
    virtual ~IProactiveProtectionRule() = default;

public:
    // Return severity(0-100) of the event sequence.
    // The higher the severity, the more the event sequence is like a threat.
    virtual outcome::result<std::uint8_t> apply(
        std::span<std::reference_wrapper<IEvent>> event_seq) = 0;
};
}  // namespace xavcore
