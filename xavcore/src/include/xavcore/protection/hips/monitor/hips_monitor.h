#pragma once

#include <spdlog/logger.h>
#include <spdlog/spdlog.h>

#include <outcome/config.hpp>
#include <outcome/outcome.hpp>

#include "hips_monitor.skel.h"

namespace outcome = OUTCOME_V2_NAMESPACE;

namespace xavcore {
class HipsMonitor {
public:
    HipsMonitor(spdlog::logger& logger);
    ~HipsMonitor();
    HipsMonitor(const HipsMonitor&) = delete;
    HipsMonitor& operator=(const HipsMonitor&) = delete;
    HipsMonitor(HipsMonitor&&) = delete;
    HipsMonitor& operator=(HipsMonitor&&) = delete;

public:
    outcome::result<void> start();
    outcome::result<void> stop();

private:
    static int event_callback(void* ctx, void* data, std::size_t size);

private:
    enum class Status { Stopped, Running };

    Status status_;
    spdlog::logger* logger_;
    hips_monitor_bpf* skel_;
    std::jthread monitor_thread_;
};
}  // namespace xavcore
