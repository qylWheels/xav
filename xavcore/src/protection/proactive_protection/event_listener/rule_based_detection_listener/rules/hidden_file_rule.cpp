#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/hidden_file_rule.h"

#include <fcntl.h>
#include <sys/syscall.h>

#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
HiddenFileRule::HiddenFileRule() = default;

HiddenFileRule::~HiddenFileRule() = default;

std::string HiddenFileRule::name() { return "hidden_file_rule"; }

std::string HiddenFileRule::description() {
    return "A rule to detect hidden file creation";
}

outcome::result<std::uint8_t> HiddenFileRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t HiddenFileRule::event_seq_size_hint() { return 1; }

outcome::result<void> HiddenFileRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);

        bool id_and_arg_match =
            (syscall_event.id == SYS_creat ||
             (syscall_event.id == SYS_open &&
              (syscall_event.args[1]) & O_CREAT) ||
             (syscall_event.id == SYS_openat &&
              (syscall_event.args[2]) & O_CREAT) ||
             syscall_event.id == SYS_openat2);
        if (!id_and_arg_match) {
            return outcome::success();
        }

        std::string path;
        switch (syscall_event.id) {
            case SYS_creat:
                path = std::get<CreatSyscallAdditionalData>(
                           syscall_event.additional_data)
                           .path.value_or("");
                break;
            case SYS_open:
                path = std::get<OpenSyscallAdditionalData>(
                           syscall_event.additional_data)
                           .path.value_or("");
                break;
            case SYS_openat:
                path = std::get<OpenatSyscallAdditionalData>(
                           syscall_event.additional_data)
                           .path.value_or("");
                break;
            case SYS_openat2:
                path = std::get<Openat2SyscallAdditionalData>(
                           syscall_event.additional_data)
                           .path.value_or("");
                break;
            default:
                return outcome::success();
        }

        std::regex re("/\\..*");
        if (std::regex_search(path, re)) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info = HiddenFileRuleWarningInfo(path);
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> HiddenFileRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> HiddenFileRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
