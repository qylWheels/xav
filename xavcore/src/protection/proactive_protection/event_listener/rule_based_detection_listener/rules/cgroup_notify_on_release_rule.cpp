#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/cgroup_notify_on_release_rule.h"

#include <sys/syscall.h>

#include <cstdlib>
#include <regex>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
CgroupNotifyOnReleaseRule::CgroupNotifyOnReleaseRule() = default;

CgroupNotifyOnReleaseRule::~CgroupNotifyOnReleaseRule() = default;

std::string CgroupNotifyOnReleaseRule::name() {
    return "cgroup_notify_on_release_rule";
}

std::string CgroupNotifyOnReleaseRule::description() {
    return "A rule to detect modification of cgroup notify-on-release file";
}

outcome::result<std::uint8_t> CgroupNotifyOnReleaseRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());

            bool id_match = (syscall_event.id == SYS_write);
            if (!id_match) {
                continue;
            }

            std::string path;
            path = std::get<WriteSyscallAdditionalData>(
                       syscall_event.additional_data)
                       .fd_path.value();

            std::regex r{".*/notify_on_release"};
            if (std::regex_match(path, r)) {
                return 70;
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t CgroupNotifyOnReleaseRule::event_seq_size_hint() { return 1; }
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
