#pragma once

#include <deque>

#include "xavagent/edr/behavioral_protection/event.h"

namespace xavagent {
class IEventSequenceSimilarity {
public:
    virtual ~IEventSequenceSimilarity() = default;
    virtual double calc_similarity(const std::deque<Event>& a,
                                   const std::deque<Event>& b) = 0;
};
}  // namespace xavagent
