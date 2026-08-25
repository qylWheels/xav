#pragma once

#include <spdlog/spdlog.h>

#include <atomic>
#include <cstdint>
#include <outcome/config.hpp>
#include <string_view>
#include <thread>
#include <unordered_set>

#include "xavcore/scan/scan_interfaces.h"
#include "xavcore/types/malware_info.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
class IOnAccessScannerEventListener {
public:
    virtual ~IOnAccessScannerEventListener() = default;

public:
    virtual void on_event(const std::string_view path,
                          const types::MalwareInfo& info) = 0;
};

class OnAccessScanner {
public:
    OnAccessScanner(spdlog::logger& logger, IScanStrategy& scan_strategy);
    ~OnAccessScanner();
    OnAccessScanner(const OnAccessScanner&) = delete;
    OnAccessScanner& operator=(const OnAccessScanner&) = delete;
    OnAccessScanner(OnAccessScanner&&) = delete;
    OnAccessScanner& operator=(OnAccessScanner&&) = delete;

public:
    outcome::result<void> start_monitoring();
    outcome::result<void> stop_monitoring();
    void set_scan_strategy(IScanStrategy& scan_strategy);
    IScanStrategy* get_scan_strategy() const;
    void add_event_listener(IOnAccessScannerEventListener& listener);
    void remove_event_listener(IOnAccessScannerEventListener& listener);

public:
    std::uint64_t scanned_object_count() const {
        return this->scanned_object_count_;
    }
    std::uint64_t blocked_object_count() const {
        return this->blocked_object_count_;
    }

private:
    enum class Status {
        Stopped,
        Running,
    };

private:
    int fanfd_;
    char* buf_;
    spdlog::logger* logger_;
    IScanStrategy* scan_strategy_;
    Status status_;
    std::jthread monitoring_thread_;
    std::unordered_set<IOnAccessScannerEventListener*> event_listeners_;

    // Statistics.
    std::atomic_uint64_t scanned_object_count_;
    std::atomic_uint64_t blocked_object_count_;
};
}  // namespace xavcore
