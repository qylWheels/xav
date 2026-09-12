#pragma once

#include <cstdint>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <outcome/config.hpp>
#include <outcome/outcome.hpp>
#include <system_error>

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
namespace app {
namespace proactive_protection_module_api {
struct StatusInfo {
    enum class Status {
        Running,
        Stopped,
    } status;

    std::uint64_t active_proc_count;
    std::uint64_t suspicious_proc_count;
    std::uint64_t malicious_proc_count;

    std::uint64_t event_count;
    std::uint64_t violate_rules_event_count;
};

class Api {
public:
    Api() = default;
    ~Api() = default;
    Api(const Api&) = delete;
    Api& operator=(const Api&) = delete;
    Api(Api&&) = delete;
    Api& operator=(Api&&) = delete;

private:
    outcome::result<nlohmann::json> status() {
        return nlohmann::json{
            {"status", StatusInfo::Status::Running},
            {"active_proc_count", 0},
            {"suspicious_proc_count", 0},
            {"malicious_proc_count", 0},
            {"event_count", 0},
            {"violate_rules_event_count", 0},
        };
    }

public:
    outcome::result<nlohmann::json> dispatcher(nlohmann::json req) {
        try {
            std::string method = req["method"].get<std::string>();
            if (method == "status") {
                return this->status();
            }
        } catch (...) {
            return std::errc::invalid_argument;
        }
        return std::errc::not_supported;
    }
};
}  // namespace proactive_protection_module_api
}  // namespace app
}  // namespace xavcore
