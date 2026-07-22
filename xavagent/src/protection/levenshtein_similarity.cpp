#include "levenshtein_similarity.h"

#include <algorithm>
#include <cstddef>
#include <rapidfuzz/fuzz.hpp>
#include <rapidfuzz/rapidfuzz_all.hpp>
#include <vector>

namespace xavagent {
double LevenshteinSimilarity::calc_similarity(const std::deque<Event>& a,
                                              const std::deque<Event>& b) {
    std::size_t n = a.size();
    std::size_t m = b.size();

    // dp[i][j] represents distance between a[0..i-1] and b[0..j-1].
    std::vector<std::vector<double>> dp(n + 1, std::vector<double>(m + 1));

    // Initialize boundary.
    for (int i = 0; i <= n; ++i) {
        dp[i][0] = i;
    }
    for (int j = 0; j <= m; ++j) {
        dp[0][j] = j;
    }

    // Fill DP table.
    for (int i = 1; i <= n; ++i) {
        for (int j = 1; j <= m; ++j) {
            dp[i][j] =
                std::min({dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                          dp[i - 1][j - 1] + (1 - this->event_struct_similarity(
                                                      a[i - 1], b[j - 1]))});
        }
    }

    return 1 - dp[n][m] / (double)std::max(n, m);
}

double LevenshteinSimilarity::event_struct_similarity(const Event& a,
                                                      const Event& b) {
    if (a.index() != b.index()) {
        return 0.0;
    }

    if (std::holds_alternative<FileEvent>(a) &&
        std::holds_alternative<FileEvent>(b)) {
        return this->file_event_struct_similarity(std::get<FileEvent>(a),
                                                  std::get<FileEvent>(b));
    }

    return 0.0;
}

double LevenshteinSimilarity::file_event_struct_similarity(const FileEvent& a,
                                                           const FileEvent& b) {
    // Calculate similarity of file event type mask.
    double event_type_mask_similarity = 0.0;
    double event_type_mask_weight = 0.2;
    int same_bit = 0,
        total_bit = static_cast<int>(FileEvent::FileEventType::Count);
    for (int i = 0; i < total_bit; ++i) {
        if (a.event_type_mask[i] == b.event_type_mask[i]) {
            ++same_bit;
        }
    }
    event_type_mask_similarity = (double)same_bit / (double)total_bit;

    // Calculate similarity of process.
    double proc_similarity = this->process_struct_similarity(a.proc, b.proc);
    double proc_weight = 0.2;

    // Calculate similarity of path1.
    double path1_similarity = rapidfuzz::fuzz::ratio(a.path1, b.path1) / 100.0;
    double path1_weight = 0.2;

    // Calculate similarity of path2.
    double path2_similarity = 0.0;
    double path2_weight = 0.2;
    if (a.path2.has_value() && b.path2.has_value()) {
        path2_similarity =
            rapidfuzz::fuzz::ratio(a.path2.value(), b.path2.value()) / 100.0;
    } else if (!a.path2.has_value() && !b.path2.has_value()) {
        path2_similarity = 1.0;
    } else {
        path2_similarity = 0.0;
    }

    auto stat_opt_similarity =
        [](const std::optional<std::filesystem::file_status>& a,
           const std::optional<std::filesystem::file_status>& b) {
            if (a.has_value() && b.has_value()) {
                // Just do it simply for now.
                return (a->permissions() == b->permissions()) * 0.5 +
                       (a->type() == b->type()) * 0.5;
            } else if (!a.has_value() && !b.has_value()) {
                return 1.0;
            } else {
                return 0.0;
            }
        };

    // Calculate similarity of stat1 and stat2.
    double stat1_similarity = 0.0, stat2_similarity = 0.0;
    double stat1_weight = 0.1, stat2_weight = 0.1;
    stat1_similarity = stat_opt_similarity(a.stat1, b.stat1);
    stat2_similarity = stat_opt_similarity(a.stat2, b.stat2);

    return event_type_mask_similarity * event_type_mask_weight +
           proc_similarity * proc_weight + path1_similarity * path1_weight +
           path2_similarity * path2_weight + stat1_similarity * stat1_weight +
           stat2_similarity * stat2_weight;
}

double LevenshteinSimilarity::process_struct_similarity(const Process& a,
                                                        const Process& b) {
    // Calculate similarity of exe_path.
    double exe_path_similarity = 0.0;
    double exe_path_weight = 0.3;
    if (a.exe_path.has_value() && b.exe_path.has_value()) {
        exe_path_similarity =
            rapidfuzz::fuzz::ratio(a.exe_path.value(), b.exe_path.value()) /
            100.0;
    } else if (!a.exe_path.has_value() && !b.exe_path.has_value()) {
        exe_path_similarity = 1.0;
    } else {
        exe_path_similarity = 0.0;
    }

    // Calculate similarity of cmdline.
    double cmdline_similarity = 0.0;
    double cmdline_weight = 0.7;
    if (a.cmdline.has_value() && b.cmdline.has_value()) {
        cmdline_similarity =
            rapidfuzz::fuzz::ratio(a.cmdline.value(), b.cmdline.value()) /
            100.0;
    } else if (!a.cmdline.has_value() && !b.cmdline.has_value()) {
        cmdline_similarity = 1.0;
    } else {
        cmdline_similarity = 0.0;
    }

    return exe_path_similarity * exe_path_weight +
           cmdline_similarity * cmdline_weight;
}
}  // namespace xavagent
