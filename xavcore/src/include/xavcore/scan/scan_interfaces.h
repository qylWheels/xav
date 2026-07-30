#pragma once

#include <filesystem>
#include <optional>
#include <outcome.hpp>
#include <outcome/config.hpp>
#include <outcome/result.hpp>

#include "malware_info.pb.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
class IScanEngine {
public:
    virtual ~IScanEngine() = default;

public:
    virtual outcome::result<std::optional<malware_info::MalwareInfo>> scan(
        const std::filesystem::path& path) = 0;
};

class IScanStrategy {
public:
    virtual ~IScanStrategy() = default;

public:
    // Might return multiple result if strategy is constructed by multiple
    // scan engines.
    virtual outcome::result<
        std::vector<outcome::result<std::optional<malware_info::MalwareInfo>>>>
    scan(const std::filesystem::path& path) = 0;
};
}  // namespace xavcore
