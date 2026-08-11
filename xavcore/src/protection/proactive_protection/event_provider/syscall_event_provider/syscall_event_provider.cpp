#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event_provider.h"

#include <bits/types/struct_iovec.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <optional>
#include <outcome/success_failure.hpp>
#include <pfs/procfs.hpp>
#include <stdexcept>
#include <stop_token>
#include <system_error>

#include "syscall_event_provider.skel.h"
#include "xavcore/protection/proactive_protection/event.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/raw_syscall_event.h"

namespace xavcore {
SyscallEventProvider::SyscallEventProvider(
    ProcessStatusViewer& process_status_viewer)
    : rb_(nullptr),
      status_(Status::Stopped),
      lost_event_count_(0),
      process_status_viewer_(&process_status_viewer) {
    this->logger_ = spdlog::stderr_color_mt("ebpf_event_provider");
    this->logger_->set_level(spdlog::level::info);

    this->skel_ = syscall_event_provider_bpf::open_and_load();
    this->logger_->info("Syscall event provider loaded");
    if (!this->skel_) {
        throw std::runtime_error("Failed to open and load BPF skeleton");
    }

    // Scan procfs to initialize process status.
    for (const auto& task : pfs::procfs().get_processes()) {
        auto process = this->pid_to_process(task.id());
    }
}

SyscallEventProvider::~SyscallEventProvider() {
    if (this->status_ == Status::Started) {
        (void)this->stop();
    }
    syscall_event_provider_bpf::destroy(this->skel_);
}

outcome::result<void> SyscallEventProvider::start() {
    if (this->status_ != Status::Stopped) {
        return outcome::failure(
            std::make_error_code(std::errc::device_or_resource_busy));
    }

    int ret = syscall_event_provider_bpf::attach(this->skel_);
    if (ret) {
        return outcome::failure(std::make_error_code(std::errc::io_error));
    }
    this->rb_ =
        ring_buffer__new(bpf_map__fd(this->skel_->maps.rb),
                         SyscallEventProvider::event_callback, this, nullptr);
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

outcome::result<void> SyscallEventProvider::stop() {
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

    syscall_event_provider_bpf::detach(this->skel_);

    this->status_ = Status::Stopped;

    return outcome::success();
}

std::uint64_t SyscallEventProvider::lost_event_count() {
    return this->lost_event_count_;
}

outcome::result<void> SyscallEventProvider::listener_register(
    IEventListener& listener) {
    if (this->listeners_.find(&listener) != this->listeners_.end()) {
        return outcome::failure(std::make_error_code(std::errc::file_exists));
    }
    this->listeners_.insert(&listener);
    return outcome::success();
}

outcome::result<void> SyscallEventProvider::listener_unregister(
    IEventListener& listener) {
    if (this->listeners_.find(&listener) == this->listeners_.end()) {
        return outcome::failure(
            std::make_error_code(std::errc::no_such_file_or_directory));
    }
    this->listeners_.erase(&listener);
    return outcome::success();
}

int SyscallEventProvider::event_callback(void* ctx, void* data,
                                         std::size_t size) {
    SyscallEventProvider* self = static_cast<SyscallEventProvider*>(ctx);
    RawSyscallEvent* raw_event = static_cast<RawSyscallEvent*>(data);

    auto result = self->raw_events_to_handle_.enqueue(*raw_event);
    if (!result) {
        self->logger_->warn("Failed to enqueue raw event");
        ++self->lost_event_count_;
    }

    return 0;
}

Process SyscallEventProvider::pid_to_process(
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

std::optional<std::filesystem::path> SyscallEventProvider::fd_to_path(
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

std::optional<std::filesystem::path> SyscallEventProvider::ptr_to_path(
    std::uint32_t pid, const void* addr) noexcept {
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

void SyscallEventProvider::handle_raw_event(const RawSyscallEvent& raw_event) {
    SyscallEvent event{.timestamp{std::chrono::system_clock::now()}};

    // Dispatch event.
    switch (raw_event.syscall_id) {
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
    auto process = this->process_status_viewer_->pid_to_process(raw_event.pid);
    if (process.has_value()) {
        event.process = process.value();
    } else {
        ++this->lost_event_count_;
        return;
    }

    // Send event.
    for (auto listener : this->listeners_) {
        if (listener->is_accept(event)) {
            (void)listener->accept(event);
        }
    }
}

std::optional<std::vector<char>> SyscallEventProvider::read_process_memory(
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
}  // namespace xavcore
