#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/scheduled_task_mod_rule.h"

#include <sys/syscall.h>

#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
ScheduledTaskModRule::ScheduledTaskModRule() = default;

ScheduledTaskModRule::~ScheduledTaskModRule() = default;

std::string ScheduledTaskModRule::name() { return "scheduled_task_mod_rule"; }

std::string ScheduledTaskModRule::description() {
    return "A rule to detect modifications to scheduled tasks";
}

outcome::result<std::uint8_t> ScheduledTaskModRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t ScheduledTaskModRule::event_seq_size_hint() { return 1; }

outcome::result<void> ScheduledTaskModRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);

        // Files and directories that hold scheduling configurations.
        static const std::regex sched_file_re(
            "(/etc/crontab|/etc/cron\\.d/|/etc/anacrontab|"
            "/var/spool/cron|/var/spool/cron/crontabs/)");
        // Scheduling command line tools (crontab, at, batch).
        static const std::regex sched_cmd_re("/(crontab|at|batch)$");

        std::string path1, path2;
        bool is_exec = false;

        switch (syscall_event.id) {
            case SYS_write:
                path1 = std::get<WriteSyscallAdditionalData>(
                            syscall_event.additional_data)
                            .fd_path.value();
                break;
            case SYS_rename:
            case SYS_renameat:
            case SYS_renameat2:
                path1 = std::get<RenameSyscallAdditionalData>(
                            syscall_event.additional_data)
                            .old_path.value();
                path2 = std::get<RenameSyscallAdditionalData>(
                            syscall_event.additional_data)
                            .new_path.value();
                break;
            case SYS_execve:
            case SYS_execveat:
                path1 = std::get<ExecveSyscallAdditionalData>(
                            syscall_event.additional_data)
                            .path.value();
                is_exec = true;
                break;
            default:
                return outcome::success();
        }

        std::string matched_path;
        if (is_exec) {
            if (std::regex_search(path1, sched_cmd_re)) {
                matched_path = path1;
            }
        } else {
            if (std::regex_search(path1, sched_file_re)) {
                matched_path = path1;
            } else if (std::regex_search(path2, sched_file_re)) {
                matched_path = path2;
            }
        }

        if (!matched_path.empty()) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info = ScheduledTaskModRuleWarningInfo(
                    syscall_event.process, matched_path);
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> ScheduledTaskModRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> ScheduledTaskModRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
