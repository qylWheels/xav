#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/cgroup_release_agent_rule.h"

#include <sys/syscall.h>

#include <cstdlib>
#include <regex>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
CgroupReleaseAgentRule::CgroupReleaseAgentRule() = default;

CgroupReleaseAgentRule::~CgroupReleaseAgentRule() = default;

std::string CgroupReleaseAgentRule::name() {
    return "cgroup_release_agent_rule";
}

std::string CgroupReleaseAgentRule::description() {
    return "A rule to detect modification of cgroup release agent file";
}

outcome::result<std::uint8_t> CgroupReleaseAgentRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());

            bool id_match = (syscall_event.id == SYS_write ||
                             syscall_event.id == SYS_rename ||
                             syscall_event.id == SYS_renameat ||
                             syscall_event.id == SYS_renameat2);
            if (!id_match) {
                continue;
            }

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
                    std::abort();  // Unreachable.
            }

            std::regex r{".*release_agent"};
            if (std::regex_match(path1, r) || std::regex_match(path2, r)) {
                return 70;
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t CgroupReleaseAgentRule::event_seq_size_hint() { return 1; }
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
