#pragma once

#include <outcome.hpp>

#include "xavagent/protection/behavior_monitor.h"
#include "xavagent/protection/event.h"

namespace xavagent {
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
}  // namespace xavagent
