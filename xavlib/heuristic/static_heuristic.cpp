#include "static_heuristic.h"

#include <optional>
#include <outcome/outcome.hpp>
#include <outcome/try.hpp>
#include <vector>

namespace xavlib {
StaticHeuristicEngineManager::StaticHeuristicEngineManager() {}

StaticHeuristicEngineManager::~StaticHeuristicEngineManager() {}

std::vector<outcome::result<std::optional<malware_info::MalwareInfo>>>
StaticHeuristicEngineManager::scan(const std::filesystem::path& path) {
    std::vector<outcome::result<std::optional<malware_info::MalwareInfo>>>
        results;

    // Scan the file with all static heuristic engines.
    for (auto& engine : this->heur_engines_) {
        results.push_back(engine->scan(path));
    }

    return results;
}

void StaticHeuristicEngineManager::add_engine(
    std::shared_ptr<IStaticHeuristicEngine> engine) {
    this->heur_engines_.push_back(engine);
}

}  // namespace xavlib
