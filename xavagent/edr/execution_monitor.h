#pragma once

#include <cstdint>

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

public:
    std::uint64_t scanned_file_count() const {
        return this->scanned_file_count_;
    }
    std::uint64_t blocked_file_count() const {
        return this->blocked_file_count_;
    }

private:
    int fanfd_;
    char* buf_;
    xavlib::ExactHashEngine exact_hash_engine_;
    std::atomic_uint64_t scanned_file_count_;
    std::atomic_uint64_t blocked_file_count_;
};
}  // namespace xavagent
