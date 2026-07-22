#pragma once

#include "edr/behavioral_protection/behavior_monitor.h"
#include "syscall_monitor.skel.h"

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
    syscall_monitor_bpf* skel_;
    ring_buffer* rb_;
};
}  // namespace xavagent
