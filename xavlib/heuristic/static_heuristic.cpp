#include "static_heuristic.h"

#include <algorithm>
#include <optional>
#include <outcome/outcome.hpp>
#include <outcome/try.hpp>
#include <vector>

namespace xavlib {
StaticHeuristicEngineManager::StaticHeuristicEngineManager() {}

StaticHeuristicEngineManager::~StaticHeuristicEngineManager() {}

outcome::result<std::optional<malware_info::MalwareInfo>>
StaticHeuristicEngineManager::scan(const std::filesystem::path& path) {
    std::vector<std::optional<malware_info::MalwareInfo>> results;

    // Scan the file with all static heuristic engines.
    for (auto& engine : this->heur_engines_) {
        OUTCOME_TRY(auto result, engine->scan(path));

        // We only care about results that are not empty.
        if (result.has_value()) {
            results.push_back(result.value());
        }
    }

    // All static heuristic engines return empty results, i.e., they all
    // consider the file as clean.
    if (results.empty()) {
        return std::nullopt;
    }

    // Sort the results by score.
    std::sort(results.begin(), results.end(), [](const auto& a, const auto& b) {
        return a.value().score() > b.value().score();
    });

    // Return the result with the highest score.
    return results.front().value();
}

void StaticHeuristicEngineManager::add_engine(
    std::shared_ptr<IStaticHeuristicEngine> engine) {
    this->heur_engines_.push_back(engine);
}

}  // namespace xavlib
