#pragma once

#include <spdlog/spdlog.h>

#include <deque>
#include <memory>
#include <unordered_map>

#include "syscall_monitor.skel.h"
#include "xavagent/protection/behavior_monitor.h"
#include "xavagent/protection/event.h"
#include "xavagent/protection/event_collection/syscall_monitor/raw_syscall_event.h"

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
    virtual void start_monitoring() override;
    virtual void stop_monitoring() override;
    virtual std::span<Event> all_events() const override;
    virtual const std::unordered_map<Process, std::deque<Event>>&
    all_events_of_procs() const override;

private:
    static int event_handler(void* ctx, void* data, std::size_t size);

private:
    std::shared_ptr<spdlog::logger> logger_;
    syscall_monitor_bpf* skel_;
    ring_buffer* rb_;
    std::unordered_map<Process, std::deque<RawSyscallEvent>> events_;
};
}  // namespace xavagent
