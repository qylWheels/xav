#pragma once

#include <deque>

#include "xavcore/protection/event.h"

namespace xavcore {
class IEventSequenceSimilarity {
public:
    virtual ~IEventSequenceSimilarity() = default;
    virtual double calc_similarity(const std::deque<Event>& a,
                                   const std::deque<Event>& b) = 0;
};
}  // namespace xavcore
