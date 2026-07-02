#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "xavlib/exact_hash.h"

namespace xavagent {
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

private:
    int fanfd_;
    char* buf_;
    xavlib::ExactHashEngine exact_hash_engine_;
};
}  // namespace xavagent
