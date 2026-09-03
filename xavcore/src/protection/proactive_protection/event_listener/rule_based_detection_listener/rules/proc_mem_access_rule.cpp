#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/proc_mem_access_rule.h"

#include <sys/syscall.h>

#include <regex>

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
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());

            std::string path = std::get<ReadSyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .fd_path.value();
            std::regex re("/proc/\\d+/mem");
            if (syscall_event.id == SYS_read && std::regex_search(path, re)) {
                return 70;
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t ProcMemAccessRule::event_seq_size_hint() { return 1; }
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
