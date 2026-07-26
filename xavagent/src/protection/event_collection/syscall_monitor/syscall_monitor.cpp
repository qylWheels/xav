#include "xavagent/protection/event_collection/syscall_monitor/syscall_monitor.h"

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
#include <pfs/procfs.hpp>
#include <stdexcept>

#include "syscall_monitor.skel.h"
#include "xavagent/protection/event.h"
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

std::span<Event> SyscallMonitor::all_events() const { return {}; }

const std::unordered_map<Process, std::deque<Event>>&
SyscallMonitor::all_events_of_procs() const {
    return this->events_;
}

int SyscallMonitor::event_handler(void* ctx, void* data, std::size_t size) {
    SyscallMonitor* self = static_cast<SyscallMonitor*>(ctx);
    RawSyscallEvent* e = static_cast<RawSyscallEvent*>(data);

    // TODO: We only monitor read syscall for now.
    if (e->syscall_id != SYS_read) {
        return 0;
    }

    // Parse process info.
    Process proc{.pid = e->pid};
    try {
        proc.ppid = pfs::procfs().get_task(e->pid).get_stat().ppid;
    } catch (...) {
        proc.ppid = std::nullopt;
    }
    try {
        proc.start_time_tick =
            pfs::procfs().get_task(e->pid).get_stat().starttime;
    } catch (...) {
        proc.start_time_tick = std::nullopt;
    }
    try {
        proc.exe_path = pfs::procfs().get_task(e->pid).get_exe();
    } catch (...) {
        proc.exe_path = std::nullopt;
    }
    try {
        const auto cmd_args = pfs::procfs().get_task(e->pid).get_cmdline();
        proc.cmdline = std::accumulate(
            cmd_args.begin(), cmd_args.end(), std::string(),
            [](std::string acc, std::string arg) { return acc + " " + arg; });
    } catch (...) {
        proc.cmdline = std::nullopt;
    }

    // Parse syscall info.
    ReadSyscallEvent read_event;
    read_event.fd = e->args[0];
    read_event.buf = reinterpret_cast<void*>(e->args[1]);
    read_event.count = e->args[2];
    read_event.ret = e->ret;
    try {
        read_event.path = pfs::procfs()
                              .get_task(e->pid)
                              .get_fds()[read_event.fd]
                              .get_target();
    } catch (...) {
        read_event.path = std::nullopt;
    }
    try {
        std::vector<char> buf_content(read_event.count, 0);
        iovec local, remote;
        local.iov_base = buf_content.data();
        local.iov_len = read_event.count;
        remote.iov_base = read_event.buf;
        remote.iov_len = read_event.count;
        read_event.buf_content = buf_content;
        ssize_t ret = process_vm_readv(e->pid, &local, 1, &remote, 1, 0);
        if (ret == -1) {
            read_event.buf_content = std::nullopt;
        }
    } catch (...) {
        read_event.buf_content = std::nullopt;
    }

    // Store event.
    self->events_[proc].push_back(read_event);

    return 0;
}
}  // namespace xavagent
