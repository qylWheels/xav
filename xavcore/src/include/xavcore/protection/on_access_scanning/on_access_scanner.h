#pragma once

#include <spdlog/spdlog.h>

#include <atomic>
#include <cstdint>
#include <outcome/config.hpp>
#include <thread>

#include "xavcore/scan/scan_interfaces.h"
#include "xavcore/types/malware_info.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
class IOnAccessScannerEventListener {
public:
    virtual ~IOnAccessScannerEventListener() = default;

public:
    virtual void on_event(const MalwareInfo& info) = 0;
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

    // Statistics.
    std::atomic_uint64_t scanned_object_count_;
    std::atomic_uint64_t blocked_object_count_;
};
}  // namespace xavcore
