#include "xavcore/protection/event_provider/syscall_monitor/syscall_monitor.h"

#include <bits/types/struct_iovec.h>
#include <bpf/libbpf.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <numeric>
#include <optional>
#include <outcome/success_failure.hpp>
#include <pfs/procfs.hpp>
#include <stdexcept>
#include <stop_token>
#include <system_error>

#include "syscall_monitor.skel.h"
#include "xavcore/protection/event.h"
#include "xavcore/protection/event_provider/syscall_monitor/raw_syscall_event.h"

namespace xavcore {
SyscallMonitor::SyscallMonitor() : rb_(nullptr), status_(Status::Stopped) {
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
                                 SyscallMonitor::event_handler, this, nullptr);
    if (!this->rb_) {
        return outcome::failure(std::make_error_code(std::errc::io_error));
    }

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

int SyscallMonitor::event_handler(void* ctx, void* data, std::size_t size) {
    SyscallMonitor* self = static_cast<SyscallMonitor*>(ctx);
    RawSyscallEvent* raw_event = static_cast<RawSyscallEvent*>(data);

    Event event;

    // Dispatch event.
    switch (raw_event->syscall_id) {
        case SYS_read: {
            event.payload = self->read_event_handler(
                raw_event->args[0], reinterpret_cast<void*>(raw_event->args[1]),
                raw_event->args[2], raw_event->pid);
            break;
        }
        case SYS_write: {
            event.payload = self->write_event_handler(
                raw_event->args[0],
                reinterpret_cast<const void*>(raw_event->args[1]),
                raw_event->args[2], raw_event->pid);
            break;
        }
        default: {
            // Nothing to do.
            return 0;
        }
    }

    // Get process information.
    event.process = self->pid_to_process(raw_event->pid);

    // Send event.
    for (auto listener : self->listeners_) {
        if (listener->is_accept(event)) {
            auto ret = listener->accept(event);
            if (!ret) {
                ++self->lost_event_count_;
            }
        }
    }

    return 0;
}

Process SyscallMonitor::pid_to_process(int pid) {  // Parse process info.
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
    int pid, int fd) noexcept {
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

std::optional<std::vector<char>> SyscallMonitor::read_process_memory(
    int pid, const void* addr, size_t size) noexcept {
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
    int fd, void* buf, size_t count,
    int pid) {  // Parse syscall info.
    ReadSyscallEventPayload payload;
    payload.fd = fd;
    payload.buf = buf;
    payload.count = count;
    payload.ret = 0;
    try {
        auto fds = pfs::procfs().get_task(pid).get_fds();
        auto it = fds.find(payload.fd);
        if (it != fds.end()) {
            payload.path = it->second.get_target();
        } else {
            payload.path = std::nullopt;
        }
    } catch (...) {
        payload.path = std::nullopt;
    }
    try {
        std::vector<char> buf_content(payload.count, 0);
        iovec local, remote;
        local.iov_base = buf_content.data();
        local.iov_len = payload.count;
        remote.iov_base = payload.buf;
        remote.iov_len = payload.count;
        payload.buf_content = buf_content;
        ssize_t ret = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (ret == -1) {
            payload.buf_content = std::nullopt;
        }
    } catch (...) {
        payload.buf_content = std::nullopt;
    }
    return payload;
}

WriteSyscallEventPayload SyscallMonitor::write_event_handler(int fd,
                                                             const void* buf,
                                                             size_t count,
                                                             int pid) {
    WriteSyscallEventPayload payload;
    payload.fd = fd;
    payload.buf = buf;
    payload.count = count;
    payload.ret = 0;
    payload.path = this->fd_to_path(pid, fd);
    payload.buf_content = this->read_process_memory(pid, buf, count);

    return payload;
}
}  // namespace xavcore
