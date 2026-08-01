#pragma once

#include <concurrentqueue/moodycamel/concurrentqueue.h>
#include <spdlog/spdlog.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <thread>
#include <unordered_set>

#include "syscall_event_provider.skel.h"
#include "xavcore/protection/proactive_protection/behavior_monitor.h"
#include "xavcore/protection/proactive_protection/event.h"
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
    Process pid_to_process(std::uint32_t pid);

    // Get file path from file descriptor, return nullopt if failed.
    std::optional<std::filesystem::path> fd_to_path(std::uint32_t pid,
                                                    int fd) noexcept;

    // Get file path from pointer, return nullopt if failed.
    std::optional<std::filesystem::path> ptr_to_path(std::uint32_t pid,
                                                     const void* addr) noexcept;

    // Read memory of process.
    std::optional<std::vector<char>> read_process_memory(std::uint32_t pid,
                                                         const void* addr,
                                                         size_t size) noexcept;

private:
    void handle_raw_event(const RawSyscallEvent& raw_event);

private:  // Basic file syscall handlers.
    ReadSyscallEventPayload read_event_handler(int fd, void* buf, size_t count,
                                               ::ssize_t ret,
                                               std::uint32_t pid);
    WriteSyscallEventPayload write_event_handler(int fd, const void* buf,
                                                 size_t count, ::ssize_t ret,
                                                 std::uint32_t pid);

private:  // Directory and filesystem syscall handlers.
    UnlinkSyscallEventPayload unlink_event_handler(const char* pathname,
                                                   int ret, std::uint32_t pid);
    UnlinkatSyscallEventPayload unlinkat_event_handler(int dirfd,
                                                       const char* pathname,
                                                       int flags, int ret,
                                                       std::uint32_t pid);
    RenameSyscallEventPayload rename_event_handler(const char* oldpath,
                                                   const char* newpath, int ret,
                                                   std::uint32_t pid);
    RenameatSyscallEventPayload renameat_event_handler(
        int olddirfd, const char* oldpath, int newdirfd, const char* newpath,
        int ret, std::uint32_t pid);

    Renameat2SyscallEventPayload renameat2_event_handler(
        int olddirfd, const char* oldpath, int newdirfd, const char* newpath,
        unsigned int flags, int ret, std::uint32_t pid);

private:  // File metadata syscall handlers.
    ChmodSyscallEventPayload chmod_event_handler(const char* pathname,
                                                 mode_t mode, int ret,
                                                 std::uint32_t pid);
    FchmodSyscallEventPayload fchmod_event_handler(int fd, mode_t mode, int ret,
                                                   std::uint32_t pid);
    FchmodatSyscallEventPayload fchmodat_event_handler(int dirfd,
                                                       const char* pathname,
                                                       mode_t mode, int flags,
                                                       int ret,
                                                       std::uint32_t pid);
    Event chown_event_handler(const char* pathname, uid_t owner, gid_t group,
                              std::uint32_t pid);
    Event fchown_event_handler(int fd, uid_t owner, gid_t group,
                               std::uint32_t pid);
    Event lchown_event_handler(const char* pathname, uid_t owner, gid_t group,
                               std::uint32_t pid);
    Event fchownat_event_handler(int dirfd, const char* pathname, uid_t owner,
                                 gid_t group, int flags, std::uint32_t pid);
    Event utime_event_handler(const char* filename, const struct utimbuf* times,
                              std::uint32_t pid);
    Event utimes_event_handler(const char* filename,
                               const struct timeval* times, std::uint32_t pid);

private:  // Links syscall handlers.
    Event readlink_event_handler(const char* pathname, char* buf, size_t bufsiz,
                                 std::uint32_t pid);
    Event readlinkat_event_handler(int dirfd, const char* pathname, char* buf,
                                   size_t bufsiz, std::uint32_t pid);

private:  // High-level I/O syscall handlers.
    Event mmap_event_handler(void* addr, size_t length, int prot, int flags,
                             int fd, off_t offset, std::uint32_t pid);

private:
    enum class Status { Started, Stopped };
    Status status_;

private:
    std::shared_ptr<spdlog::logger> logger_;
    ebpf_event_provider_bpf* skel_;
    ring_buffer* rb_;
    std::unordered_set<IEventListener*> listeners_;
    std::atomic_uint64_t lost_event_count_;
    std::jthread monitor_thread_;
    moodycamel::ConcurrentQueue<RawSyscallEvent> raw_events_to_handle_;
    std::jthread handle_raw_events_thread_;
};
}  // namespace xavcore
