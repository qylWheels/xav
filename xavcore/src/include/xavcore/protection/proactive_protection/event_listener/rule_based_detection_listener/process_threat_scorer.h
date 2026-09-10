#pragma once

#include <cstdint>
#include <typeindex>
#include <unordered_map>

#include "xavcore/protection/proactive_protection/event.h"

namespace xavcore {

// Maps a rule's severity (0-100) to a weight used for scoring.
// Higher-severity actions weigh more than low-severity ones.
std::uint32_t threat_severity_to_weight(std::uint8_t severity);

// Aggregates per-process rule violations into a single 0-100 "maliciousness"
// score and a verdict, using the formula:
//
//   Risk = A * S_max + B * sum_i( w_i * min(count_i, M) ) + C * min(n, K)
//
// where, per process:
//   - S_max   : weight of the strongest (highest-weight) rule hit once;
//   - count_i : number of times rule i actually fired (raw, no dedup);
//   - w_i     : weight of rule i;
//   - min(.,M): caps how many times a single rule may contribute (anti-spam);
//   - n       : number of distinct rules hit;
//   - min(.,K): caps the diversity bonus (anti low-severity pile-up).
//
// Thread-safety: not thread-safe. Call feed()/score()/verdict() from a single
// thread (the rule listener callback thread).
class ProcessThreatScorer {
public:
    enum class Verdict { Benign, Suspicious, Malicious };

    struct Config {
        double a = 12.0;      // peak weight coefficient
        double b = 3.0;       // accumulated-evidence coefficient
        double c = 4.0;       // rule-diversity coefficient
        std::uint32_t m = 3;  // per-rule count cap
        std::uint32_t k = 5;  // diversity-count cap
        double t1 = 25.0;     // benign / suspicious boundary
        double t2 = 50.0;     // suspicious / malicious boundary
        double max_score = 100.0;
    };

    ProcessThreatScorer();
    explicit ProcessThreatScorer(Config config);

    ProcessThreatScorer(const ProcessThreatScorer&) = delete;
    ProcessThreatScorer& operator=(const ProcessThreatScorer&) = delete;
    ProcessThreatScorer(ProcessThreatScorer&&) = delete;
    ProcessThreatScorer& operator=(ProcessThreatScorer&&) = delete;

    // Record one violation of `rule` (identified by its dynamic type) by
    // `proc`, whose rule severity is `severity`.
    void feed(const Process& proc, std::type_index rule, std::uint8_t severity);

    // Recompute the current risk score for `proc`.
    double score(const Process& proc) const;

    Verdict verdict(const Process& proc) const;

    const Config& config() const { return this->config_; }

private:
    struct RuleState {
        std::uint32_t count = 0;
    };
    struct ProcessState {
        std::uint32_t s_max = 0;
        double sum_e = 0.0;
        std::unordered_map<std::type_index, RuleState> rules;
    };

    Config config_;
    std::unordered_map<Process, ProcessState> proc_states_;
};

}  // namespace xavcore
