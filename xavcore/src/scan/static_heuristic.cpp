#include "xavcore/scan/static_heuristic.h"

#include <optional>
#include <outcome/outcome.hpp>
#include <outcome/try.hpp>
#include <vector>

namespace xavcore {
StaticHeuristicEngineManager::StaticHeuristicEngineManager() {}

StaticHeuristicEngineManager::~StaticHeuristicEngineManager() {}

outcome::result<std::vector<
    outcome::result<std::optional<std::pair<std::string, types::MalwareInfo>>>>>
StaticHeuristicEngineManager::scan(const std::filesystem::path& path) {
    std::vector<outcome::result<
        std::optional<std::pair<std::string, types::MalwareInfo>>>>
        results;

    // Scan the file with all static heuristic engines.
    for (auto& engine : this->heur_engines_) {
        results.push_back(engine->scan(path));
    }

    return outcome::success(results);
}

void StaticHeuristicEngineManager::add_engine(
    std::shared_ptr<IStaticHeuristicEngine> engine) {
    this->heur_engines_.push_back(engine);
}

}  // namespace xavcore
