#include "xavagent/protection/event_listener/levenshtein.h"

namespace xavagent {
Levenshtein::Levenshtein() = default;

Levenshtein::~Levenshtein() = default;

bool Levenshtein::is_accept(const Event& event) {
    // We accept all events.
    return true;
}

outcome::result<void> Levenshtein::accept(const Event& event) {
    // TODO
    return outcome::success();
}

}  // namespace xavagent