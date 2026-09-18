#pragma once

#include <cstdint>
#include <filesystem>
#include <outcome/outcome.hpp>

#include "xavcore/types/malware_info.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xav {
namespace scan {
namespace sandbox {
class Sandbox {
public:
    Sandbox();
    ~Sandbox();
    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;
    Sandbox(Sandbox&&) = delete;
    Sandbox& operator=(Sandbox&&) = delete;

public:
    outcome::result<void> load(const std::filesystem::path& path);
    outcome::result<xavcore::types::MalwareInfo> run(std::int64_t timeout_ms);
    void reset();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace sandbox
}  // namespace scan
}  // namespace xav
