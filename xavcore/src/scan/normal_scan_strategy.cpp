#include "xavcore/scan/normal_scan_strategy.h"

#include <vector>

namespace xavcore {
NormalScanStrategy::NormalScanStrategy(
    IScanEngine& exact_hash_engine, IScanEngine& yara_static_heuristic_engine)
    : exact_hash_engine_(&exact_hash_engine),
      yara_static_heuristic_engine_(&yara_static_heuristic_engine) {}

outcome::result<
    std::vector<outcome::result<std::optional<malware_info::MalwareInfo>>>>
NormalScanStrategy::scan(const std::filesystem::path& path) {
    std::vector<outcome::result<std::optional<malware_info::MalwareInfo>>>
        results;

    auto result_from_exact_hash_engine = this->exact_hash_engine_->scan(path);
    results.push_back(result_from_exact_hash_engine);
    auto result_from_heur_engine =
        this->yara_static_heuristic_engine_->scan(path);
    results.push_back(result_from_heur_engine);

    return results;
}
}  // namespace xavcore
