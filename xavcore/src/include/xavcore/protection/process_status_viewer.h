#pragma once

#include <spdlog/logger.h>

#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_map>

#include "xavcore/protection/proactive_protection/behavior_monitor.h"

namespace xavcore {
class ProcessStatusViewer : public IEventListener {
public:
    ProcessStatusViewer(spdlog::logger& logger);
    ~ProcessStatusViewer();
    ProcessStatusViewer(const ProcessStatusViewer&) = delete;
    ProcessStatusViewer& operator=(const ProcessStatusViewer&) = delete;
    ProcessStatusViewer(ProcessStatusViewer&&) = delete;
    ProcessStatusViewer& operator=(ProcessStatusViewer&&) = delete;

public:
    virtual bool is_accept(const IEvent& event) override;
    virtual outcome::result<void> accept(const IEvent& event) override;

public:
    std::optional<Process> pid_to_process(std::uint32_t pid);

private:
    std::optional<Process> parse_pid(std::uint32_t pid);

private:  // Process status.
    std::unordered_map<std::uint32_t, std::deque<Process>> process_status_;
    spdlog::logger* logger_;
};
}  // namespace xavcore
