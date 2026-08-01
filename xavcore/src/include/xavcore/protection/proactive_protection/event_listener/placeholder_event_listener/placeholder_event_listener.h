#pragma once

#include "xavcore/protection/proactive_protection/behavior_monitor.h"

namespace xavcore {
class PlaceholderEventListener : public IEventListener {
public:
    PlaceholderEventListener() = default;
    ~PlaceholderEventListener() = default;
    PlaceholderEventListener(const PlaceholderEventListener&) = delete;
    PlaceholderEventListener& operator=(const PlaceholderEventListener&) =
        delete;
    PlaceholderEventListener(PlaceholderEventListener&&) = delete;
    PlaceholderEventListener& operator=(PlaceholderEventListener&&) = delete;

public:
    virtual bool is_accept(const Event& event) override { return true; }

    virtual outcome::result<void> accept(const Event& event) override {
        return outcome::success();
    }
};
};  // namespace xavcore
