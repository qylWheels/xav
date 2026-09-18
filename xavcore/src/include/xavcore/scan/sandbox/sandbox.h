#pragma once

#include <unicorn/unicorn.h>

#include <cstdint>
#include <filesystem>
#include <outcome/outcome.hpp>

#include "xavcore/types/malware_info.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xav {
namespace scan {
namespace sandbox {
class UcErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override { return "unicorn"; }

    std::string message(int ev) const override {
        return uc_strerror(static_cast<uc_err>(ev));
    }
};

inline const std::error_category& uc_error_category() {
    static UcErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(uc_err e) {
    return {static_cast<int>(e), uc_error_category()};
}

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
