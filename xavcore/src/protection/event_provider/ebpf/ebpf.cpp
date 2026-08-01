#include "xavcore/protection/event_provider/ebpf/ebpf.h"

#include <bits/types/struct_iovec.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <numeric>
#include <optional>
#include <outcome/success_failure.hpp>
#include <pfs/procfs.hpp>
#include <stdexcept>
#include <stop_token>
#include <system_error>

#include "syscall_monitor.skel.h"
#include "xavcore/protection/event.h"
#include "xavcore/protection/event_provider/ebpf/raw_syscall_event.h"

namespace xavcore {
SyscallMonitor::SyscallMonitor()
    : rb_(nullptr), status_(Status::Stopped), lost_event_count_(0) {
    this->logger_ = spdlog::stderr_color_mt("syscall_monitor");
    this->logger_->set_level(spdlog::level::info);

    this->skel_ = syscall_monitor_bpf::open_and_load();
    this->logger_->info("Syscall monitor ebpf loaded");
    if (!this->skel_) {
        throw std::runtime_error("Failed to open and load BPF skeleton");
    }
}

SyscallMonitor::~SyscallMonitor() {
    if (this->status_ == Status::Started) {
        (void)this->stop();
    }
    syscall_monitor_bpf::destroy(this->skel_);
}

outcome::result<void> SyscallMonitor::start() {
    if (this->status_ != Status::Stopped) {
        return outcome::failure(
            std::make_error_code(std::errc::device_or_resource_busy));
    }

    int ret = syscall_monitor_bpf::attach(this->skel_);
    if (ret) {
        return outcome::failure(std::make_error_code(std::errc::io_error));
    }
    this->rb_ = ring_buffer__new(bpf_map__fd(this->skel_->maps.rb),
                                 SyscallMonitor::event_callback, this, nullptr);
    if (!this->rb_) {
        return outcome::failure(std::make_error_code(std::errc::io_error));
    }

    // Start handling raw events in a separate thread.
    this->handle_raw_events_thread_ =
        std::jthread([this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                RawSyscallEvent raw_event;
                if (this->raw_events_to_handle_.try_dequeue(raw_event)) {
                    this->handle_raw_event(raw_event);
                }
            }
        });

    // Start monitoring in a separate thread.
    this->monitor_thread_ = std::jthread([this](std::stop_token stop) {
        while (!stop.stop_requested()) {
            int err = ring_buffer__poll(this->rb_, 1000);
            if (err < 0) {
                this->logger_->warn("Failed to poll ring buffer");
            }
        }
    });

    this->status_ = Status::Started;

    return outcome::success();
}

outcome::result<void> SyscallMonitor::stop() {
    if (this->status_ != Status::Started) {
        return outcome::failure(
            std::make_error_code(std::errc::no_such_device_or_address));
    }

    this->monitor_thread_.request_stop();
    this->monitor_thread_.join();

    this->handle_raw_events_thread_.request_stop();
    this->handle_raw_events_thread_.join();

    ring_buffer__free(this->rb_);
    this->rb_ = nullptr;

    syscall_monitor_bpf::detach(this->skel_);

    this->status_ = Status::Stopped;

    return outcome::success();
}

std::uint64_t SyscallMonitor::lost_event_count() {
    return this->lost_event_count_;
}

outcome::result<void> SyscallMonitor::listener_register(
    IEventListener& listener) {
    if (this->listeners_.find(&listener) != this->listeners_.end()) {
        return outcome::failure(std::make_error_code(std::errc::file_exists));
    }
    this->listeners_.insert(&listener);
    return outcome::success();
}

outcome::result<void> SyscallMonitor::listener_unregister(
    IEventListener& listener) {
    if (this->listeners_.find(&listener) == this->listeners_.end()) {
        return outcome::failure(
            std::make_error_code(std::errc::no_such_file_or_directory));
    }
    this->listeners_.erase(&listener);
    return outcome::success();
}

int SyscallMonitor::event_callback(void* ctx, void* data, std::size_t size) {
    SyscallMonitor* self = static_cast<SyscallMonitor*>(ctx);
    RawSyscallEvent* raw_event = static_cast<RawSyscallEvent*>(data);

    auto result = self->raw_events_to_handle_.enqueue(*raw_event);
    if (!result) {
        self->logger_->warn("Failed to enqueue raw event");
        ++self->lost_event_count_;
    }

    return 0;
}

Process SyscallMonitor::pid_to_process(
    std::uint32_t pid) {  // Parse process info.
    Process proc{.pid = pid};
    try {
        proc.ppid = pfs::procfs().get_task(pid).get_stat().ppid;
    } catch (...) {
        proc.ppid = std::nullopt;
    }
    try {
        proc.start_time_tick = pfs::procfs().get_task(pid).get_stat().starttime;
    } catch (...) {
        proc.start_time_tick = std::nullopt;
    }
    try {
        proc.exe_path = pfs::procfs().get_task(pid).get_exe();
    } catch (...) {
        proc.exe_path = std::nullopt;
    }
    try {
        const auto cmd_args = pfs::procfs().get_task(pid).get_cmdline();
        proc.cmdline = std::accumulate(
            cmd_args.begin(), cmd_args.end(), std::string(),
            [](std::string acc, std::string arg) { return acc + " " + arg; });
    } catch (...) {
        proc.cmdline = std::nullopt;
    }
    return proc;
}

std::optional<std::filesystem::path> SyscallMonitor::fd_to_path(
    std::uint32_t pid, int fd) noexcept {
    try {
        auto fds = pfs::procfs().get_task(pid).get_fds();
        auto it = fds.find(fd);
        if (it != fds.end()) {
            return it->second.get_target();
        } else {
            return std::nullopt;
        }
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::filesystem::path> SyscallMonitor::ptr_to_path(
    std::uint32_t pid, const void* addr) noexcept {
    return std::nullopt;
    try {
        char buf[1];
        std::string path_str;
        iovec local, remote;
        std::size_t i = 0;
        local.iov_base = buf;
        local.iov_len = 1;
        remote.iov_len = 1;
        do {
            remote.iov_base = reinterpret_cast<void*>((std::size_t)addr + i);
            ssize_t ret = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (ret == -1) {
                return std::nullopt;
            } else {
                path_str += buf;
                i += 1;
            }
        } while (buf[0] != '\0' && i < PATH_MAX);
        return path_str;
    } catch (...) {
        return std::nullopt;
    }
}

void SyscallMonitor::handle_raw_event(const RawSyscallEvent& raw_event) {
    Event event;

    // Dispatch event.
    switch (raw_event.syscall_id) {
        case SYS_read: {
            event.payload = this->read_event_handler(
                raw_event.args[0], reinterpret_cast<void*>(raw_event.args[1]),
                raw_event.args[2], raw_event.ret, raw_event.pid);
            break;
        }
        case SYS_write: {
            event.payload = this->write_event_handler(
                raw_event.args[0],
                reinterpret_cast<const void*>(raw_event.args[1]),
                raw_event.args[2], raw_event.ret, raw_event.pid);
            break;
        }
        case SYS_unlink: {
            event.payload = this->unlink_event_handler(
                reinterpret_cast<const char*>(raw_event.args[0]), raw_event.ret,
                raw_event.pid);
            break;
        }
        case SYS_unlinkat: {
            event.payload = this->unlinkat_event_handler(
                raw_event.args[0],
                reinterpret_cast<const char*>(raw_event.args[1]),
                raw_event.args[2], raw_event.ret, raw_event.pid);
            break;
        }
        case SYS_rename: {
            event.payload = this->rename_event_handler(
                reinterpret_cast<const char*>(raw_event.args[0]),
                reinterpret_cast<const char*>(raw_event.args[1]), raw_event.ret,
                raw_event.pid);
            break;
        }
        case SYS_renameat: {
            event.payload = this->renameat_event_handler(
                raw_event.args[0],
                reinterpret_cast<const char*>(raw_event.args[1]),
                raw_event.args[2],
                reinterpret_cast<const char*>(raw_event.args[3]), raw_event.ret,
                raw_event.pid);
            break;
        }
        case SYS_renameat2: {
            event.payload = this->renameat2_event_handler(
                raw_event.args[0],
                reinterpret_cast<const char*>(raw_event.args[1]),
                raw_event.args[2],
                reinterpret_cast<const char*>(raw_event.args[3]),
                raw_event.args[4], raw_event.ret, raw_event.pid);
            break;
        }
        case SYS_chmod: {
            event.payload = this->chmod_event_handler(
                reinterpret_cast<const char*>(raw_event.args[0]),
                raw_event.args[1], raw_event.ret, raw_event.pid);
            break;
        }
        case SYS_fchmod: {
            event.payload =
                this->fchmod_event_handler(raw_event.args[0], raw_event.args[1],
                                           raw_event.ret, raw_event.pid);
            break;
        }
        case SYS_fchmodat: {
            event.payload = this->fchmodat_event_handler(
                raw_event.args[0],
                reinterpret_cast<const char*>(raw_event.args[1]),
                raw_event.args[2], raw_event.args[3], raw_event.ret,
                raw_event.pid);
            break;
        }
        default: {
            // Nothing to do.
            return;
        }
    }

    // Get process information.
    event.process = this->pid_to_process(raw_event.pid);

    // Send event.
    for (auto listener : this->listeners_) {
        if (listener->is_accept(event)) {
            (void)listener->accept(event);
        }
    }
}

std::optional<std::vector<char>> SyscallMonitor::read_process_memory(
    std::uint32_t pid, const void* addr, size_t size) noexcept {
    try {
        std::vector<char> memory(size, 0);
        iovec local, remote;
        local.iov_base = memory.data();
        local.iov_len = size;
        remote.iov_base = const_cast<void*>(addr);
        remote.iov_len = size;
        ssize_t ret = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (ret == -1) {
            return std::nullopt;
        } else {
            return memory;
        }
    } catch (...) {
        return std::nullopt;
    }
}

ReadSyscallEventPayload SyscallMonitor::read_event_handler(
    int fd, void* buf, size_t count, ::ssize_t ret,
    std::uint32_t pid) {  // Parse syscall info.
    ReadSyscallEventPayload payload;
    payload.fd = fd;
    payload.buf = buf;
    payload.count = count;
    payload.ret = ret;
    payload.path = this->fd_to_path(pid, fd);
    payload.buf_content = this->read_process_memory(pid, buf, count);

    return payload;
}

WriteSyscallEventPayload SyscallMonitor::write_event_handler(
    int fd, const void* buf, size_t count, ::ssize_t ret, std::uint32_t pid) {
    WriteSyscallEventPayload payload;
    payload.fd = fd;
    payload.buf = buf;
    payload.count = count;
    payload.ret = ret;
    payload.path = this->fd_to_path(pid, fd);
    payload.buf_content = this->read_process_memory(pid, buf, count);

    return payload;
}

UnlinkSyscallEventPayload SyscallMonitor::unlink_event_handler(
    const char* pathname, int ret, std::uint32_t pid) {
    UnlinkSyscallEventPayload payload;
    payload.pathname = pathname;
    payload.ret = ret;
    payload.path = this->ptr_to_path(pid, pathname);

    return payload;
}

UnlinkatSyscallEventPayload SyscallMonitor::unlinkat_event_handler(
    int dirfd, const char* pathname, int flags, int ret, std::uint32_t pid) {
    UnlinkatSyscallEventPayload payload;
    payload.dirfd = dirfd;
    payload.pathname = pathname;
    payload.flags = flags;
    payload.ret = ret;
    auto dirpath = this->fd_to_path(pid, dirfd);
    auto filepath = this->ptr_to_path(pid, pathname);
    try {
        if (dirpath.has_value() && filepath.has_value()) {
            payload.path = dirpath.value() / filepath.value();
        } else {
            payload.path = std::nullopt;
        }
    } catch (...) {
        payload.path = std::nullopt;
    }

    return payload;
}

RenameSyscallEventPayload SyscallMonitor::rename_event_handler(
    const char* oldpath, const char* newpath, int ret, std::uint32_t pid) {
    RenameSyscallEventPayload payload;
    payload.oldpath = oldpath;
    payload.newpath = newpath;
    payload.ret = ret;
    payload.oldpath_class = this->ptr_to_path(pid, oldpath);
    payload.newpath_class = this->ptr_to_path(pid, newpath);

    return payload;
}

RenameatSyscallEventPayload SyscallMonitor::renameat_event_handler(
    int olddirfd, const char* oldpath, int newdirfd, const char* newpath,
    int ret, std::uint32_t pid) {
    RenameatSyscallEventPayload payload;
    payload.olddirfd = olddirfd;
    payload.newdirfd = newdirfd;
    payload.oldpath = oldpath;
    payload.newpath = newpath;
    payload.ret = ret;
    payload.oldpath_class = this->ptr_to_path(pid, oldpath);
    payload.newpath_class = this->ptr_to_path(pid, newpath);

    return payload;
}

Renameat2SyscallEventPayload SyscallMonitor::renameat2_event_handler(
    int olddirfd, const char* oldpath, int newdirfd, const char* newpath,
    unsigned int flags, int ret, std::uint32_t pid) {
    Renameat2SyscallEventPayload payload;
    payload.olddirfd = olddirfd;
    payload.newdirfd = newdirfd;
    payload.oldpath = oldpath;
    payload.newpath = newpath;
    payload.flags = flags;
    payload.ret = ret;
    payload.oldpath_class = this->ptr_to_path(pid, oldpath);
    payload.newpath_class = this->ptr_to_path(pid, newpath);

    return payload;
}

ChmodSyscallEventPayload SyscallMonitor::chmod_event_handler(
    const char* pathname, mode_t mode, int ret, std::uint32_t pid) {
    ChmodSyscallEventPayload payload;
    payload.pathname = pathname;
    payload.mode = mode;
    payload.ret = ret;
    payload.path = this->ptr_to_path(pid, pathname);

    return payload;
}

FchmodSyscallEventPayload SyscallMonitor::fchmod_event_handler(
    int fd, mode_t mode, int ret, std::uint32_t pid) {
    FchmodSyscallEventPayload payload;
    payload.fd = fd;
    payload.mode = mode;
    payload.ret = ret;
    payload.path = this->fd_to_path(pid, fd);

    return payload;
}

FchmodatSyscallEventPayload SyscallMonitor::fchmodat_event_handler(
    int dirfd, const char* pathname, mode_t mode, int flags, int ret,
    std::uint32_t pid) {
    FchmodatSyscallEventPayload payload;
    payload.dirfd = dirfd;
    payload.pathname = pathname;
    payload.mode = mode;
    payload.flags = flags;
    payload.ret = ret;
    auto dirpath = this->fd_to_path(pid, dirfd);
    auto filepath = this->ptr_to_path(pid, pathname);
    try {
        if (dirpath.has_value() && filepath.has_value()) {
            payload.path = dirpath.value() / filepath.value();
        } else {
            payload.path = std::nullopt;
        }
    } catch (...) {
        payload.path = std::nullopt;
    }

    return payload;
}

}  // namespace xavcore
