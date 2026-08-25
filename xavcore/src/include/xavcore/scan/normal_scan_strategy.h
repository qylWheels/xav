#pragma once

#include "xavcore/scan/scan_interfaces.h"

namespace xavcore {
class NormalScanStrategy : public IScanStrategy {
public:
    NormalScanStrategy(IScanEngine &exact_hash_engine,
                       IScanEngine &yara_static_heuristic_engine);
    ~NormalScanStrategy() = default;

public:
    virtual outcome::result<std::vector<outcome::result<
        std::optional<std::pair<std::string, types::MalwareInfo>>>>>
    scan(const std::filesystem::path &path) override;

private:
    IScanEngine *exact_hash_engine_;
    IScanEngine *yara_static_heuristic_engine_;
};
}  // namespace xavcore
