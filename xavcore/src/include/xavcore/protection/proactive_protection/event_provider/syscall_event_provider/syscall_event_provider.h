#pragma once

#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <spdlog/spdlog.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <unordered_set>
#include <vector>

#include "syscall_event_provider.skel.h"
#include "xavcore/protection/proactive_protection/behavior_monitor.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/raw_syscall_event.h"
#include "xavcore/protection/process_status_viewer.h"

namespace xavcore {
struct SyscallEvent : public IEvent {
    std::chrono::time_point<std::chrono::system_clock> timestamp;
    Process process;
    std::uint32_t id;
    std::vector<std::uint64_t> args;
    std::uint64_t ret;
};

class SyscallEventProvider : public IEventProvider {
public:
    SyscallEventProvider(ProcessStatusViewer& process_status_viewer);
    ~SyscallEventProvider();
    SyscallEventProvider(const SyscallEventProvider&) = delete;
    SyscallEventProvider& operator=(const SyscallEventProvider&) = delete;
    SyscallEventProvider(SyscallEventProvider&&) = delete;
    SyscallEventProvider& operator=(SyscallEventProvider&&) = delete;

public:
    virtual outcome::result<void> start() override;
    virtual outcome::result<void> stop() override;
    virtual std::uint64_t lost_event_count() override;
    virtual outcome::result<void> listener_register(
        IEventListener& listener) override;
    virtual outcome::result<void> listener_unregister(
        IEventListener& listener) override;

private:
    static int event_callback(void* ctx, void* data, std::size_t size);

private:
    void handle_raw_event(const RawSyscallEvent& raw_event);

private:
    enum class Status { Started, Stopped };
    Status status_;

private:
    std::shared_ptr<spdlog::logger> logger_;
    syscall_event_provider_bpf* skel_;
    ring_buffer* rb_;
    std::unordered_set<IEventListener*> listeners_;
    std::atomic_uint64_t lost_event_count_;
    std::jthread monitor_thread_;
    moodycamel::ConcurrentQueue<RawSyscallEvent> raw_events_to_handle_;
    std::jthread handle_raw_events_thread_;
    ProcessStatusViewer* process_status_viewer_;
};
}  // namespace xavcore
