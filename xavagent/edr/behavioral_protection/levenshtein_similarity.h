#pragma once

#include <deque>

#include "xavagent/edr/behavioral_protection/event.h"
#include "xavagent/edr/behavioral_protection/event_seq_similarity.h"

namespace xavagent {
class LevenshteinSimilarity : public IEventSequenceSimilarity {
public:
    virtual double calc_similarity(const std::deque<Event>& a,
                                   const std::deque<Event>& b) override;

private:
    double event_struct_similarity(const Event& a, const Event& b);
    double file_event_struct_similarity(const FileEvent& a, const FileEvent& b);
    double process_struct_similarity(const Process& a, const Process& b);
};
}  // namespace xavagent
