#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/rcd_modification_rule.h"

#include <sys/syscall.h>

#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
RcdModificationRule::RcdModificationRule() = default;

RcdModificationRule::~RcdModificationRule() = default;

std::string RcdModificationRule::name() { return "rcd_modification_rule"; }

std::string RcdModificationRule::description() {
    return "A rule to detect modifications to system runlevel (rcd) scripts";
}

outcome::result<std::uint8_t> RcdModificationRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t RcdModificationRule::event_seq_size_hint() { return 1; }

outcome::result<void> RcdModificationRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);

        // Runlevel/init script directories: /etc/rc.d/, /etc/init.d/ and
        // /etc/rc*.d/ (e.g. /etc/rc0.d/ .. /etc/rcS.d/).
        static const std::regex rcd_file_re(
            "/(etc/rc\\.d/|etc/init\\.d/|etc/rc[0-9S]\\.d/)");
        // Runlevel management command line tools.
        static const std::regex rcd_cmd_re("/(update-rc\\.d|chkconfig)$");

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
            if (std::regex_search(path1, rcd_cmd_re)) {
                matched_path = path1;
            }
        } else {
            if (std::regex_search(path1, rcd_file_re)) {
                matched_path = path1;
            } else if (std::regex_search(path2, rcd_file_re)) {
                matched_path = path2;
            }
        }

        if (!matched_path.empty()) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info = RcdModificationRuleWarningInfo(
                    syscall_event.process, matched_path);
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> RcdModificationRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> RcdModificationRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
