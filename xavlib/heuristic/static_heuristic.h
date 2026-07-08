#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <vector>

#include "xavcommon/malware_info.pb.h"

namespace xavlib {
class IStaticHeuristicEngine {
public:
    virtual ~IStaticHeuristicEngine() = default;

public:
    std::optional<malware_info::MalwareInfo> scan(
        const std::filesystem::path& path);
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
    std::optional<malware_info::MalwareInfo> scan(
        const std::filesystem::path& path);
    void add_engine(std::shared_ptr<IStaticHeuristicEngine> engine);

private:
    std::vector<std::shared_ptr<IStaticHeuristicEngine>> heur_engines_;
};
}  // namespace xavlib
