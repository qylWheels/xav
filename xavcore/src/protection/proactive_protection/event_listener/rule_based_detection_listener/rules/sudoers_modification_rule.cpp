#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/sudoers_modification_rule.h"

#include <sys/syscall.h>

#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
SudoersModificationRule::SudoersModificationRule() = default;

SudoersModificationRule::~SudoersModificationRule() = default;

std::string SudoersModificationRule::name() {
    return "sudoers_modification_rule";
}

std::string SudoersModificationRule::description() {
    return "A rule to detect modifications to sudo configuration";
}

outcome::result<std::uint8_t> SudoersModificationRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t SudoersModificationRule::event_seq_size_hint() { return 1; }

outcome::result<void> SudoersModificationRule::push_event(
    const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);

        // /etc/sudoers and files under /etc/sudoers.d/.
        static const std::regex sudoers_re("(/etc/sudoers|/etc/sudoers\\.d/)");

        std::string path1, path2;
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
            default:
                return outcome::success();
        }

        std::string matched_path;
        if (std::regex_search(path1, sudoers_re)) {
            matched_path = path1;
        } else if (std::regex_search(path2, sudoers_re)) {
            matched_path = path2;
        }

        if (!matched_path.empty()) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info = SudoersModificationRuleWarningInfo(
                    syscall_event.process, matched_path);
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> SudoersModificationRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> SudoersModificationRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
