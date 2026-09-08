#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/process_threat_scorer.h"

#include <algorithm>

namespace xavcore {

std::uint32_t threat_severity_to_weight(std::uint8_t severity) {
    if (severity >= 60) {
        return 3;
    }
    if (severity >= 30) {
        return 2;
    }
    return 1;
}

ProcessThreatScorer::ProcessThreatScorer() = default;

ProcessThreatScorer::ProcessThreatScorer(Config config) : config_(config) {}

void ProcessThreatScorer::feed(const Process& proc, std::type_index rule,
                               std::uint8_t severity) {
    ProcessState& ps = this->proc_states_[proc];
    RuleState& st = ps.rules[rule];
    const std::uint32_t weight = threat_severity_to_weight(severity);

    if (weight > ps.s_max) {
        ps.s_max = weight;
    }
    // Only the first M firings of a rule contribute to the accumulated
    // evidence, so repeated abuse cannot inflate the score unboundedly.
    if (st.count < this->config_.m) {
        ps.sum_e += weight;
    }
    ++st.count;
}

double ProcessThreatScorer::score(const Process& proc) const {
    auto it = this->proc_states_.find(proc);
    if (it == this->proc_states_.end()) {
        return 0.0;
    }
    const ProcessState& ps = it->second;
    const std::uint32_t n = static_cast<std::uint32_t>(ps.rules.size());
    double risk = this->config_.a * ps.s_max + this->config_.b * ps.sum_e +
                  this->config_.c * std::min<std::uint32_t>(n, this->config_.k);
    return std::min(risk, this->config_.max_score);
}

ProcessThreatScorer::Verdict ProcessThreatScorer::verdict(
    const Process& proc) const {
    const double risk = this->score(proc);
    if (risk < this->config_.t1) {
        return Verdict::Benign;
    }
    if (risk < this->config_.t2) {
        return Verdict::Suspicious;
    }
    return Verdict::Malicious;
}

}  // namespace xavcore
