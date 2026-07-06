#pragma once

namespace xavagent {
// Score of a process.
// The score of a process is the average of the scores of its components.
// 0.0 is the lowest score, 1.0 is the highest score.
// The higher the score, the more malicious the process is.
struct MaliciousScore {
    double proc_score;
    double fs_score;
    double net_score;
};
}  // namespace xavagent
