#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/proc_mem_access_rule.h"

#include <sys/syscall.h>

#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
ProcMemAccessRule::ProcMemAccessRule() = default;

ProcMemAccessRule::~ProcMemAccessRule() = default;

std::string ProcMemAccessRule::name() { return "proc_mem_access_rule"; }

std::string ProcMemAccessRule::description() {
    return "A rule to detect /proc/[pid]/mem access";
}

outcome::result<std::uint8_t> ProcMemAccessRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t ProcMemAccessRule::event_seq_size_hint() { return 1; }

outcome::result<void> ProcMemAccessRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id == SYS_read) {
            std::string path = std::get<ReadSyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .fd_path.value();
            std::regex re("/proc/\\d+/mem");
            if (std::regex_search(path, re)) {
                for (auto cb : this->callbacks_on_warning_) {
                    auto info = ProcMemAccessRuleWarningInfo(path);
                    (*cb)(info);
                }
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> ProcMemAccessRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> ProcMemAccessRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
