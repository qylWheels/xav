#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "malware_info.h"

namespace xav {
class ExecutionMonitor {
public:
    ExecutionMonitor();
    ~ExecutionMonitor();
    ExecutionMonitor(const ExecutionMonitor&) = delete;
    ExecutionMonitor& operator=(const ExecutionMonitor&) = delete;
    ExecutionMonitor(ExecutionMonitor&&) = delete;
    ExecutionMonitor& operator=(ExecutionMonitor&&) = delete;

public:
    void start_monitoring();
    void stop_monitoring();
};
}  // namespace xav
