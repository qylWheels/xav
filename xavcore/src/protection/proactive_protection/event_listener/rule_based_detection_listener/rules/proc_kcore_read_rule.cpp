#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/proc_kcore_read_rule.h"

#include <sys/syscall.h>

#include <regex>

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
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());

            std::string path = std::get<ReadSyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .fd_path.value();
            std::regex re("/proc/kcore");
            if (syscall_event.id == SYS_read && std::regex_search(path, re)) {
                return 40;
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t ProcKcoreReadRule::event_seq_size_hint() { return 1; }
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
