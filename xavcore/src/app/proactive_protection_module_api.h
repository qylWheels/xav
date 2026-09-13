#pragma once

#include <cstdint>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>

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
    nlohmann::json status() {
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
    nlohmann::json dispatch(nlohmann::json req) {
        try {
            std::string method = req["method"].get<std::string>();
            if (method ==
                "xavcore::app::proactive_protection_module_api::Api::status") {
                auto result = this->status();
                return nlohmann::json{
                    {"jsonrpc", "2.0"},
                    {"result", result},
                    {"id", req["id"]},
                };
            }
        } catch (...) {
            return {{"jsonrpc", "2.0"},
                    {"error",
                     {
                         {"code", -32602},
                         {"message", "Invalid params"},
                     }},
                    {"id", req["id"]}};
        }
        return {{"jsonrpc", "2.0"},
                {"error",
                 {
                     {"code", -32601},
                     {"message", "Method not found"},
                 }},
                {"id", req["id"]}};
    }
};
}  // namespace proactive_protection_module_api
}  // namespace app
}  // namespace xavcore
