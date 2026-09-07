#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/sched_debug_recon_rule.h"

#include <sys/syscall.h>

#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
SchedDebugReconRule::SchedDebugReconRule() = default;

SchedDebugReconRule::~SchedDebugReconRule() = default;

std::string SchedDebugReconRule::name() { return "sched_debug_recon_rule"; }

std::string SchedDebugReconRule::description() {
    return "A rule to detect reconnaissance through scheduler debug files";
}

outcome::result<std::uint8_t> SchedDebugReconRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    return std::errc::not_supported;
}

std::size_t SchedDebugReconRule::event_seq_size_hint() { return 1; }

outcome::result<void> SchedDebugReconRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);
        if (syscall_event.id != SYS_read) {
            return outcome::success();
        }

        const std::string path = std::get<ReadSyscallAdditionalData>(
                                     syscall_event.additional_data)
                                     .fd_path.value();
        std::regex re(
            "/proc/sched_debug|/sys/kernel/debug/sched/debug");
        if (std::regex_search(path, re)) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info =
                    SchedDebugReconRuleWarningInfo(syscall_event.process, path);
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> SchedDebugReconRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> SchedDebugReconRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
