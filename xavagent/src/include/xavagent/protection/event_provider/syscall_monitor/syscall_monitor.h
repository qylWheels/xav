#pragma once

#include <spdlog/spdlog.h>

#include <memory>
#include <thread>
#include <unordered_set>

#include "syscall_monitor.skel.h"
#include "xavagent/protection/behavior_monitor.h"

namespace xavagent {
class SyscallMonitor : public IEventProvider {
public:
    SyscallMonitor();
    ~SyscallMonitor();
    SyscallMonitor(const SyscallMonitor&) = delete;
    SyscallMonitor& operator=(const SyscallMonitor&) = delete;
    SyscallMonitor(SyscallMonitor&&) = delete;
    SyscallMonitor& operator=(SyscallMonitor&&) = delete;

public:
    virtual outcome::result<void> start() override;
    virtual outcome::result<void> stop() override;
    virtual std::uint64_t lost_event_count() override;
    virtual outcome::result<void> listener_register(
        IEventListener& listener) override;
    virtual outcome::result<void> listener_unregister(
        IEventListener& listener) override;

private:
    static int event_handler(void* ctx, void* data, std::size_t size);

private:
    enum class Status { Started, Stopped };
    Status status_;

private:
    std::shared_ptr<spdlog::logger> logger_;
    syscall_monitor_bpf* skel_;
    ring_buffer* rb_;
    std::unordered_set<IEventListener*> listeners_;
    std::uint64_t lost_event_count_;
    std::jthread monitor_thread_;
};
}  // namespace xavagent
