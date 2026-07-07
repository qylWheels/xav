#pragma once

#include <linux/fanotify.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <unordered_map>

#include "event.h"
#include "spdlog/logger.h"

namespace xavagent {
class BehaviorMonitor {
public:
    BehaviorMonitor();
    ~BehaviorMonitor();
    BehaviorMonitor(const BehaviorMonitor&) = delete;
    BehaviorMonitor& operator=(const BehaviorMonitor&) = delete;
    BehaviorMonitor(BehaviorMonitor&&) = delete;
    BehaviorMonitor& operator=(BehaviorMonitor&&) = delete;

public:
    void start_monitoring();
    void stop_monitoring();

public:
    std::uint64_t total_event_count() const { return this->total_event_count_; }

    std::uint64_t suspicious_event_count() const {
        return this->suspicious_event_count_;
    }

private:
    std::optional<std::string> get_path_from_dfid_name_record(
        fanotify_event_info_fid* dfid_name_record);

private:
    std::optional<int> get_proc_ppid(int pid);
    std::optional<unsigned long long> get_proc_start_time_tick(int pid);
    std::optional<std::string> get_proc_exe_path(int pid);
    std::optional<std::string> get_proc_cmdline(int pid);
    std::optional<std::string> get_proc_raw_stat(int pid, int n);

private:
    int fanfd_;
    char* fanbuf_;
    int mount_fd_;
    std::unordered_map<Process, std::deque<Event>> procs_events_;
    std::atomic_uint64_t total_event_count_;
    std::atomic_uint64_t suspicious_event_count_;
    std::shared_ptr<spdlog::logger> logger_;
};
}  // namespace xavagent
