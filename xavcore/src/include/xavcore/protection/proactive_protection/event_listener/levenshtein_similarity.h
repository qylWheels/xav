#pragma once

#include <deque>

#include "xavcore/protection/event.h"
#include "xavcore/protection/event_seq_similarity.h"

namespace xavcore {
class LevenshteinSimilarity : public IEventSequenceSimilarity {
public:
    virtual double calc_similarity(const std::deque<Event>& a,
                                   const std::deque<Event>& b) override;

private:
    double event_struct_similarity(const Event& a, const Event& b);
    double file_event_struct_similarity(const FileEvent& a, const FileEvent& b);
    double process_struct_similarity(const Process& a, const Process& b);
};
}  // namespace xavcore
