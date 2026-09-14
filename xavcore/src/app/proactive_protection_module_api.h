#pragma once

#include <cstdint>
#include <exception>
#include <mutex>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <outcome/success_failure.hpp>
#include <string>
#include <utility>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_based_detection_listener.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event_provider.h"

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
    Api(RuleBasedDetectionListener& rule_based_detection_listener,
        SyscallEventProvider& syscall_event_provider)
        : rule_based_detection_listener_(&rule_based_detection_listener),
          syscall_event_provider_(&syscall_event_provider) {};
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
            {"status", this->syscall_event_provider_->status() ==
                               SyscallEventProvider::Status::Started
                           ? "Running"
                           : "Stopped"},
            {"suspicious_proc_count", suspicious_proc_count},
            {"malicious_proc_count", malicious_proc_count},
            {"event_count", event_count},
            {"violate_rules_event_count", violate_rules_event_count},
        };
    }

    outcome::result<void> start() {
        auto result = this->syscall_event_provider_->start();
        if (!result) {
            return result.error();
        }
        return outcome::success();
    }

    outcome::result<void> stop() {
        auto result = this->syscall_event_provider_->stop();
        if (!result) {
            return result.error();
        }
        return outcome::success();
    }

public:
    std::optional<nlohmann::json> dispatch(nlohmann::json req) {
        if (!req.is_object()) {
            return this->error_response(nullptr, -32600, "Invalid Request");
        }

        // Notification, no need to response.
        if (!req.contains("id")) {
            return std::nullopt;
        }

        const nlohmann::json id = req["id"];

        std::string method;
        try {
            method = req["method"].get<std::string>();
        } catch (const std::exception&) {
            return this->error_response(id, -32602, "Invalid params");
        }

        if (method ==
            "xavcore::app::proactive_protection_module_api::Api::status") {
            return this->success_response(id, this->status());
        } else if (method ==
                   "xavcore::app::proactive_protection_module_api::Api::"
                   "start") {
            auto result = this->start();
            if (result) {
                return this->success_response(
                    id, nlohmann::json{{"status", "Running"}});
            } else {
                return this->error_response(id, -32000,
                                            result.error().message());
            }
        } else if (method ==
                   "xavcore::app::proactive_protection_module_api::Api::stop") {
            auto result = this->stop();
            if (result) {
                return this->success_response(
                    id, nlohmann::json{{"status", "Stopped"}});
            } else {
                return this->error_response(id, -32000,
                                            result.error().message());
            }
        }
        return this->error_response(id, -32601, "Method not found");
    }

private:
    nlohmann::json success_response(const nlohmann::json& id,
                                    nlohmann::json result) {
        return nlohmann::json{
            {"jsonrpc", "2.0"},
            {"result", std::move(result)},
            {"id", id},
        };
    }

    nlohmann::json error_response(const nlohmann::json& id, int code,
                                  const std::string& message) {
        return nlohmann::json{
            {"jsonrpc", "2.0"},
            {"error", {{"code", code}, {"message", message}}},
            {"id", id},
        };
    }

private:
    RuleBasedDetectionListener* rule_based_detection_listener_;
    SyscallEventProvider* syscall_event_provider_;
};
}  // namespace proactive_protection_module_api
}  // namespace app
}  // namespace xavcore
