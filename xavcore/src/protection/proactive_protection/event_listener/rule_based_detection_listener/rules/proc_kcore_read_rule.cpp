#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/proc_kcore_read_rule.h"

#include <sys/syscall.h>

#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
ProcKcoreReadRule::ProcKcoreReadRule() = default;

ProcKcoreReadRule::~ProcKcoreReadRule() = default;

std::string ProcKcoreReadRule::name() { return "proc_kcore_read_rule"; }

std::string ProcKcoreReadRule::description() {
    return "A rule to detect /proc/kcore read";
}

outcome::result<std::uint8_t> ProcKcoreReadRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t ProcKcoreReadRule::event_seq_size_hint() { return 1; }

outcome::result<void> ProcKcoreReadRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id == SYS_read) {
            std::string path = std::get<ReadSyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .fd_path.value();
            std::regex re("/proc/kcore");
            if (std::regex_search(path, re)) {
                for (auto cb : this->callbacks_on_warning_) {
                    auto info = ProcKcoreReadRuleWarningInfo(path);
                    (*cb)(info);
                }
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> ProcKcoreReadRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> ProcKcoreReadRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
