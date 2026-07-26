#pragma once

#include <linux/fanotify.h>

#include <cstdint>
#include <memory>
#include <outcome.hpp>
#include <outcome/config.hpp>
#include <outcome/result.hpp>

#include "xavagent/protection/event.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavagent {
class IEventListener;

class IEventProvider {
public:
    virtual ~IEventProvider() = default;

public:
    // These two function shouldn't block the caller.
    virtual outcome::result<void> start() = 0;
    virtual outcome::result<void> stop() = 0;

    virtual std::uint64_t lost_event_count() = 0;
    virtual outcome::result<void> listener_register(
        std::shared_ptr<IEventListener> listener) = 0;
    virtual outcome::result<void> listener_unregister(
        std::shared_ptr<IEventListener> listener) = 0;
};

class IEventListener {
public:
    virtual ~IEventListener() = default;

public:
    // Procedure: accept? -> enqueue -> on_event.
    virtual bool is_accept(const Event& event) = 0;
    virtual outcome::result<void> accept(const Event& event) = 0;
};

}  // namespace xavagent
