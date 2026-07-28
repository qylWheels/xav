#pragma once

#include <spdlog/spdlog.h>
#include <sys/types.h>

#include <cstddef>
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
    int read_event_handler(int fd, void* buf, size_t count);
    int write_event_handler(int fd, const void* buf, size_t count);

private:  // Directory and filesystem syscall handlers.
    int unlink_event_handler(const char* pathname);
    int unlinkat_event_handler(int dirfd, const char* pathname, int flags);
    int rename_event_handler(const char* oldpath, const char* newpath);
    int renameat_event_handler(int olddirfd, const char* oldpath, int newdirfd,
                               const char* newpath);
    int renameat2_event_handler(int olddirfd, const char* oldpath, int newdirfd,
                                const char* newpath, int flags);

private:  // File metadata syscall handlers.
    int chmod_event_handler(const char* pathname, mode_t mode);
    int fchmod_event_handler(int fd, mode_t mode);
    int fchmodat_event_handler(int dirfd, const char* pathname, mode_t mode,
                               int flags);
    int chown_event_handler(const char* pathname, uid_t owner, gid_t group);
    int fchown_event_handler(int fd, uid_t owner, gid_t group);
    int lchown_event_handler(const char* pathname, uid_t owner, gid_t group);
    int fchownat_event_handler(int dirfd, const char* pathname, uid_t owner,
                               gid_t group, int flags);
    int utime_event_handler(const char* filename, const struct utimbuf* times);
    int utimes_event_handler(const char* filename, const struct timeval* times);

private:  // Links syscall handlers.
    ssize_t readlink_event_handler(const char* pathname, char* buf,
                                   size_t bufsiz);
    ssize_t readlinkat_event_handler(int dirfd, const char* pathname, char* buf,
                                     size_t bufsiz);

private:  // High-level I/O syscall handlers.
    void* mmap_event_handler(void* addr, size_t length, int prot, int flags,
                             int fd, off_t offset);

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
