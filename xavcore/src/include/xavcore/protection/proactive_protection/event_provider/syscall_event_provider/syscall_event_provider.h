#pragma once

#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <spdlog/spdlog.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <unordered_set>
#include <vector>

#include "syscall_event_provider.skel.h"
#include "xavcore/protection/proactive_protection/behavior_monitor.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/raw_syscall_event.h"

namespace xavcore {
class SyscallEventProvider : public IEventProvider {
public:
    SyscallEventProvider();
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
    struct RawSyscallEventWrapper {
        RawSyscallEvent raw_event;
        std::vector<std::vector<std::uint8_t>> additional_data;
    };

private:
    void handle_raw_event_wrapper(
        const RawSyscallEventWrapper& raw_event_wrapper);

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
    moodycamel::ConcurrentQueue<RawSyscallEventWrapper>
        raw_event_wrappers_to_handle_;
    std::jthread handle_raw_events_thread_;
    std::chrono::time_point<std::chrono::system_clock> sys_boot_time_point_;
};
}  // namespace xavcore
