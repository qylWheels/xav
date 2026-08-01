#pragma once

#include <outcome.hpp>

#include "xavcore/protection/proactive_protection/behavior_monitor.h"
#include "xavcore/protection/proactive_protection/event.h"

namespace xavcore {
class Levenshtein : public IEventListener {
public:
    Levenshtein();
    ~Levenshtein();
    Levenshtein(const Levenshtein&) = delete;
    Levenshtein& operator=(const Levenshtein&) = delete;
    Levenshtein(Levenshtein&&) = delete;
    Levenshtein& operator=(Levenshtein&&) = delete;

public:
    virtual bool is_accept(const Event& event) override;
    virtual outcome::result<void> accept(const Event& event) override;
};
}  // namespace xavcore
