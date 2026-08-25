#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <outcome/outcome.hpp>
#include <vector>

#include "xavcore/scan/scan_interfaces.h"
#include "xavcore/types/malware_info.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
class IStaticHeuristicEngine : public IScanEngine {
public:
    virtual ~IStaticHeuristicEngine() = default;
};

class StaticHeuristicEngineManager {
public:
    StaticHeuristicEngineManager();
    ~StaticHeuristicEngineManager();
    StaticHeuristicEngineManager(const StaticHeuristicEngineManager&) = delete;
    StaticHeuristicEngineManager& operator=(
        const StaticHeuristicEngineManager&) = delete;
    StaticHeuristicEngineManager(StaticHeuristicEngineManager&&) = delete;
    StaticHeuristicEngineManager& operator=(StaticHeuristicEngineManager&&) =
        delete;

public:
    outcome::result<std::vector<outcome::result<
        std::optional<std::pair<std::string, types::MalwareInfo>>>>>
    scan(const std::filesystem::path& path);
    void add_engine(std::shared_ptr<IStaticHeuristicEngine> engine);

private:
    std::vector<std::shared_ptr<IStaticHeuristicEngine>> heur_engines_;
};
}  // namespace xavcore
