#include "xavagent/protection/event_listener/levenshtein.h"

namespace xavagent {
bool is_accept(const Event& event) {
    // We accept all events.
    return true;
}

outcome::result<void> accept(const Event& event) {
    // TODO
    return outcome::success();
}

}  // namespace xavagent