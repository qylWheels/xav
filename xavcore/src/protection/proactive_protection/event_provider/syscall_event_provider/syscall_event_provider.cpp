#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event_provider.h"

#include <bits/types/struct_iovec.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <outcome/success_failure.hpp>
#include <pfs/procfs.hpp>
#include <stdexcept>
#include <stop_token>
#include <system_error>

#include "syscall_event_provider.skel.h"
#include "xavcore/protection/proactive_protection/event.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/raw_syscall_event.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
SyscallEventProvider::SyscallEventProvider()
    : rb_(nullptr), status_(Status::Stopped), lost_event_count_(0) {
    this->logger_ = spdlog::stderr_color_mt("ebpf_event_provider");
    this->logger_->set_level(spdlog::level::info);

    this->skel_ = syscall_event_provider_bpf::open_and_load();
    this->logger_->info("Syscall event provider loaded");
    if (!this->skel_) {
        throw std::runtime_error("Failed to open and load BPF skeleton");
    }

    // Calculate the system boot time point.
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    auto boot_time =
        std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec);
    this->sys_boot_time_point_ = std::chrono::system_clock::now() - boot_time;
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

    if (raw_event->syscall_id == 0) {
        if (raw_event->additional_str_count == 1) {
            std::uint64_t raw_event_addr =
                reinterpret_cast<std::uint64_t>(raw_event);
            std::string path((char*)(raw_event_addr + sizeof(*raw_event)));
            std::uint64_t args[6] = {0};
            std::memmove(args, raw_event->args, sizeof(args));
            std::uint64_t ret;
            std::memmove(&ret, (const void*)&raw_event->ret, sizeof(ret));
            self->logger_->info("read({}, {:#x}, {}) = {}", path, args[1],
                                args[2], ret);
        }
    }

    auto result = self->raw_events_to_handle_.enqueue(*raw_event);
    if (!result) {
        self->logger_->warn("Failed to enqueue raw event");
        ++self->lost_event_count_;
    }

    return 0;
}

void SyscallEventProvider::handle_raw_event(const RawSyscallEvent& raw_event) {
    SyscallEvent event;
    event.timestamp = this->sys_boot_time_point_ +
                      std::chrono::nanoseconds(raw_event.timestamp);
    event.process = {.pid = raw_event.pid,
                     .start_time_point = this->sys_boot_time_point_ +
                                         std::chrono::nanoseconds(
                                             raw_event.proc_start_boottime)};
    event.id = raw_event.syscall_id;
    if (raw_event.enter_captured) {
        std::uint64_t args[6];
        std::memcpy(args, raw_event.args, sizeof(args));
        event.args = std::vector(std::begin(args), std::end(args));
    }
    if (raw_event.exit_captured) {
        event.ret = raw_event.ret;
    }

    // if (event.args.empty()) {
    //     this->logger_->info("[{}] {} called syscall: {}() = {}",
    //                         event.timestamp.time_since_epoch().count(),
    //                         event.process.pid, event.id, event.ret);
    // } else {
    //     this->logger_->info(
    //         "[{}] {} called syscall: {}({}, {}, {}, {}, {}, {}) = {}",
    //         event.timestamp.time_since_epoch().count(), event.process.pid,
    //         event.id, event.args[0], event.args[1], event.args[2],
    //         event.args[3], event.args[4], event.args[5], event.ret);
    // }

    // Send event.
    for (auto listener : this->listeners_) {
        if (listener->is_accept(event)) {
            (void)listener->accept(event);
        }
    }
}
}  // namespace xavcore
