#pragma once

#include <spdlog/spdlog.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
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
    Process pid_to_process(int pid);

private:  // Basic file syscall handlers.
    Event read_event_handler(int fd, void* buf, size_t count, int pid);
    Event write_event_handler(int fd, const void* buf, size_t count, int pid);

private:  // Directory and filesystem syscall handlers.
    Event unlink_event_handler(const char* pathname, std::int64_t pid);
    Event unlinkat_event_handler(int dirfd, const char* pathname, int flags,
                                 std::int64_t pid);
    Event rename_event_handler(const char* oldpath, const char* newpath,
                               std::int64_t pid);
    Event renameat_event_handler(int olddirfd, const char* oldpath,
                                 int newdirfd, const char* newpath,
                                 std::int64_t pid);
    Event renameat2_event_handler(int olddirfd, const char* oldpath,
                                  int newdirfd, const char* newpath, int flags,
                                  std::int64_t pid);

private:  // File metadata syscall handlers.
    Event chmod_event_handler(const char* pathname, mode_t mode,
                              std::int64_t pid);
    Event fchmod_event_handler(int fd, mode_t mode, std::int64_t pid);
    Event fchmodat_event_handler(int dirfd, const char* pathname, mode_t mode,
                                 int flags, std::int64_t pid);
    Event chown_event_handler(const char* pathname, uid_t owner, gid_t group,
                              std::int64_t pid);
    Event fchown_event_handler(int fd, uid_t owner, gid_t group,
                               std::int64_t pid);
    Event lchown_event_handler(const char* pathname, uid_t owner, gid_t group,
                               std::int64_t pid);
    Event fchownat_event_handler(int dirfd, const char* pathname, uid_t owner,
                                 gid_t group, int flags, std::int64_t pid);
    Event utime_event_handler(const char* filename, const struct utimbuf* times,
                              std::int64_t pid);
    Event utimes_event_handler(const char* filename,
                               const struct timeval* times, std::int64_t pid);

private:  // Links syscall handlers.
    Event readlink_event_handler(const char* pathname, char* buf, size_t bufsiz,
                                 std::int64_t pid);
    Event readlinkat_event_handler(int dirfd, const char* pathname, char* buf,
                                   size_t bufsiz, std::int64_t pid);

private:  // High-level I/O syscall handlers.
    Event mmap_event_handler(void* addr, size_t length, int prot, int flags,
                             int fd, off_t offset, std::int64_t pid);

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
