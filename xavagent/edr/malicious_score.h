#pragma once

#include <cstdint>

namespace xavagent {
// Score of a process.
// The score of a process is the average of the scores of its components.
// 0 is the lowest score, 100 is the highest score.
// The higher the score, the more malicious the process is.
struct MaliciousScore {
    std::uint8_t proc_score;
    std::uint8_t fs_score;
    std::uint8_t net_score;
};
}  // namespace xavagent
