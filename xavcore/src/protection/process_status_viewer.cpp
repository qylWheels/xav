#include "xavcore/protection/process_status_viewer.h"

#include <numeric>
#include <pfs/procfs.hpp>

#include "pfs/procfs.hpp"

namespace xavcore {
ProcessStatusViewer::ProcessStatusViewer(spdlog::logger& logger)
    : logger_(&logger) {}

ProcessStatusViewer::~ProcessStatusViewer() = default;

bool ProcessStatusViewer::is_accept(const Event& event) {
    return std::holds_alternative<ProcessLifecycleEvent>(event);
}

outcome::result<void> ProcessStatusViewer::accept(const Event& event) {
    ProcessLifecycleEvent process_lifecycle_event =
        std::get<ProcessLifecycleEvent>(event);
    std::visit(
        [this](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, ProcessCreateEvent>) {
                auto it = this->process_status_.find(arg.pid);
                if (it == this->process_status_.end()) {
                    this->process_status_.emplace(
                        arg.pid, Processes{
                                     .active_process{this->parse_pid(arg.pid)},
                                     .history_processes{},
                                 });
                } else {
                    it->second.active_process = this->parse_pid(arg.pid);
                }
            } else if constexpr (std::is_same_v<T, ProcessExitEvent>) {
                auto it = this->process_status_.find(arg.pid);
                if (it == this->process_status_.end()) {
                    auto proc = this->parse_pid(arg.pid);
                    if (proc.has_value()) {
                        this->process_status_.emplace(
                            arg.pid, Processes{
                                         .active_process{},
                                         .history_processes{proc.value()},
                                     });
                    }
                } else {
                    if (it->second.active_process.has_value()) {
                        it->second.history_processes.emplace_back(
                            it->second.active_process.value());
                    }
                    it->second.active_process = std::nullopt;
                }
            } else {
            }
        },
        process_lifecycle_event);
    return outcome::success();
}
std::optional<Process> ProcessStatusViewer::pid_to_process(std::uint32_t pid) {
    auto it = this->process_status_.find(pid);
    if (it != this->process_status_.end()) {
        return it->second.active_process;
    }
    return this->parse_pid(pid);
}

std::optional<Process> ProcessStatusViewer::parse_pid(std::uint32_t pid) {
    // Unnullable fields.
    Process proc{.pid = pid};
    try {
        proc.start_time_tick = pfs::procfs().get_task(pid).get_stat().starttime;
    } catch (...) {
        return std::nullopt;
    }

    // Nullable fields.
    try {
        proc.ppid = pfs::procfs().get_task(pid).get_stat().ppid;
    } catch (...) {
        proc.ppid = std::nullopt;
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
}  // namespace xavcore
