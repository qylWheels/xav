#pragma once

#include <spdlog/spdlog.h>

#include <memory>

#include "syscall_monitor.skel.h"
#include "xavagent/protection/behavior_monitor.h"

namespace xavagent {
class SyscallMonitor : public IBehaviorMonitor {
public:
    SyscallMonitor();
    ~SyscallMonitor();
    SyscallMonitor(const SyscallMonitor&) = delete;
    SyscallMonitor& operator=(const SyscallMonitor&) = delete;
    SyscallMonitor(SyscallMonitor&&) = delete;
    SyscallMonitor& operator=(SyscallMonitor&&) = delete;

public:
    virtual void start_monitoring();
    virtual void stop_monitoring();
    virtual std::span<Event> all_events() const;
    virtual std::size_t event_count() const;

private:
    static int event_handler(void* ctx, void* data, std::size_t size);

private:
    std::shared_ptr<spdlog::logger> logger_;
    syscall_monitor_bpf* skel_;
    ring_buffer* rb_;
};
}  // namespace xavagent
