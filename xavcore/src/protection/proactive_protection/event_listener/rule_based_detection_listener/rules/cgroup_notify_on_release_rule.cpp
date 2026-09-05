#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/cgroup_notify_on_release_rule.h"

#include <sys/syscall.h>

#include <cstdlib>
#include <outcome/success_failure.hpp>
#include <regex>
#include <system_error>

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
    return std::errc::not_supported;
}

std::size_t CgroupNotifyOnReleaseRule::event_seq_size_hint() { return 1; }

outcome::result<void> CgroupNotifyOnReleaseRule::push_event(const IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);

        bool id_match = (syscall_event.id == SYS_write);
        if (!id_match) {
            return outcome::success();
        }

        std::string path;
        path =
            std::get<WriteSyscallAdditionalData>(syscall_event.additional_data)
                .fd_path.value();

        std::regex r{".*notify_on_release"};
        if (std::regex_match(path, r)) {
            for (auto cb : this->callbacks_on_warning_) {
                auto info = CgroupNotifyOnReleaseRuleWarningInfo(path);
                (*cb)(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> CgroupNotifyOnReleaseRule::register_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.insert(&cb);
    return outcome::success();
}

outcome::result<void> CgroupNotifyOnReleaseRule::unregister_warning_callback(
    std::function<void(const IRuleWarningInfo&)>& cb) {
    this->callbacks_on_warning_.erase(&cb);
    return outcome::success();
}
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
