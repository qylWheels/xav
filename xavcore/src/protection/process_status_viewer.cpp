#include "xavcore/protection/process_status_viewer.h"

#include <numeric>
#include <pfs/procfs.hpp>

#include "xavcore/protection/proactive_protection/event_provider/process_lifecycle_event_provider/process_lifecycle_event_provider.h"

namespace xavcore {
ProcessStatusViewer::ProcessStatusViewer(spdlog::logger& logger)
    : logger_(&logger) {}

ProcessStatusViewer::~ProcessStatusViewer() = default;

bool ProcessStatusViewer::is_accept(const IEvent& event) {
    return typeid(event) == typeid(ProcessCreateEvent) ||
           typeid(event) == typeid(ProcessExitEvent);
}

outcome::result<void> ProcessStatusViewer::accept(const IEvent& event) {
    if (typeid(event) == typeid(ProcessCreateEvent)) {
        auto e = dynamic_cast<const ProcessCreateEvent&>(event);
        auto it = this->process_status_.find(e.pid);
        if (it == this->process_status_.end()) {
            auto proc = this->parse_pid(e.pid);
            if (proc.has_value()) {
                this->process_status_.emplace(
                    e.pid, std::deque<Process>{proc.value()});
            }
        } else {
            auto proc = this->parse_pid(e.pid);
            if (proc.has_value()) {
                it->second.emplace_back(proc.value());
            }
        }
    } else if (typeid(event) == typeid(ProcessExitEvent)) {
        auto e = dynamic_cast<const ProcessExitEvent&>(event);
        auto it = this->process_status_.find(e.pid);
        if (it == this->process_status_.end()) {
            auto proc = this->parse_pid(e.pid);
            if (proc.has_value()) {
                this->process_status_.emplace(
                    e.pid, std::deque<Process>{proc.value()});
            }
        } else {
            if (it->second.back().pid != e.pid) {
                auto proc = this->parse_pid(e.pid);
                if (proc.has_value()) {
                    it->second.emplace_back(proc.value());
                }
            }
        }
    } else {
        logger_->error("Unknown process lifecycle event");
    }

    return outcome::success();
}
std::optional<Process> ProcessStatusViewer::pid_to_process(std::uint32_t pid) {
    auto it = this->process_status_.find(pid);
    if (it != this->process_status_.end() && !it->second.empty()) {
        return it->second.back();
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
