#pragma once

#include <cstdint>
#include <mutex>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_based_detection_listener.h"

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
    Api(RuleBasedDetectionListener& rule_based_detection_listener)
        : rule_based_detection_listener_(&rule_based_detection_listener) {};
    ~Api() = default;
    Api(const Api&) = delete;
    Api& operator=(const Api&) = delete;
    Api(Api&&) = delete;
    Api& operator=(Api&&) = delete;

private:
    nlohmann::json status() {
        RuleBasedDetectionListener* listener =
            this->rule_based_detection_listener_;
        std::lock_guard<std::recursive_mutex> lock(listener->mutex());

        std::uint64_t suspicious_proc_count = 0;
        std::uint64_t malicious_proc_count = 0;
        std::uint64_t event_count = 0;
        std::uint64_t violate_rules_event_count = 0;
        for (const auto& [process, events] : listener->proc_syscall_events()) {
            event_count += events.size();
            switch (listener->threat_verdict(process)) {
                case ProcessThreatScorer::Verdict::Suspicious:
                    ++suspicious_proc_count;
                    break;
                case ProcessThreatScorer::Verdict::Malicious:
                    ++malicious_proc_count;
                    break;
                default:
                    break;
            }
        }
        for (const auto& [process, violations] :
             listener->proc_violated_events()) {
            violate_rules_event_count += violations.size();
        }

        return nlohmann::json{
            {"status", StatusInfo::Status::Running},
            {"suspicious_proc_count", suspicious_proc_count},
            {"malicious_proc_count", malicious_proc_count},
            {"event_count", event_count},
            {"violate_rules_event_count", violate_rules_event_count},
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

private:
    RuleBasedDetectionListener* rule_based_detection_listener_;
};
}  // namespace proactive_protection_module_api
}  // namespace app
}  // namespace xavcore
