#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/dynamic_code_loading.h"

#include <sys/mman.h>
#include <sys/syscall.h>

#include <cstdlib>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
DynamicCodeLoadingRule::DynamicCodeLoadingRule() = default;

DynamicCodeLoadingRule::~DynamicCodeLoadingRule() = default;

std::string DynamicCodeLoadingRule::name() {
    return "dynamic_code_loading_rule";
}

std::string DynamicCodeLoadingRule::description() {
    return "A rule to detect dynamic code loading";
}

outcome::result<std::uint8_t> DynamicCodeLoadingRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());

            if (syscall_event.id == SYS_mprotect &&
                syscall_event.args[2] == (PROT_WRITE | PROT_EXEC)) {
                return 60;
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t DynamicCodeLoadingRule::event_seq_size_hint() { return 1; }
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
