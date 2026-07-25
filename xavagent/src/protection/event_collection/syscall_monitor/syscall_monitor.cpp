#include "xavagent/protection/event_collection/syscall_monitor/syscall_monitor.h"

#include <bpf/libbpf.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sys/resource.h>
#include <unistd.h>

#include <format>
#include <stdexcept>

#include "syscall_monitor.skel.h"
#include "xavagent/protection/event_collection/syscall_monitor/raw_syscall_event.h"

namespace xavagent {
SyscallMonitor::SyscallMonitor() : rb_(nullptr) {
    this->logger_ = spdlog::stderr_color_mt("syscall_monitor");
    this->logger_->set_level(spdlog::level::info);

    this->skel_ = syscall_monitor_bpf::open_and_load();
    this->logger_->info("Syscall monitor ebpf loaded");
    if (!this->skel_) {
        throw std::runtime_error("Failed to open and load BPF skeleton");
    }
}

SyscallMonitor::~SyscallMonitor() {
    if (this->rb_) {
        ring_buffer__free(this->rb_);
    }
    syscall_monitor_bpf::destroy(this->skel_);
}

void SyscallMonitor::start_monitoring() {
    int ret = syscall_monitor_bpf::attach(this->skel_);
    if (ret) {
        throw std::runtime_error("Failed to attach BPF skeleton");
    }
    this->rb_ = ring_buffer__new(bpf_map__fd(this->skel_->maps.rb),
                                 SyscallMonitor::event_handler, this, nullptr);
    while (true) {
        int err = ring_buffer__poll(this->rb_, 1000);
        if (err < 0) {
            throw std::runtime_error("Failed to poll ring buffer");
        }
    }
}

void SyscallMonitor::stop_monitoring() {
    if (this->rb_) {
        ring_buffer__free(this->rb_);
        this->rb_ = nullptr;
    }
    syscall_monitor_bpf::detach(this->skel_);
}

std::span<Event> SyscallMonitor::all_events() const {}

std::size_t SyscallMonitor::event_count() const {}

int SyscallMonitor::event_handler(void* ctx, void* data, std::size_t size) {
    SyscallMonitor* self = static_cast<SyscallMonitor*>(ctx);
    struct RawSyscallEvent* e = static_cast<struct RawSyscallEvent*>(data);
    self->events_.push_back(*e);
    return 0;
}
}  // namespace xavagent
