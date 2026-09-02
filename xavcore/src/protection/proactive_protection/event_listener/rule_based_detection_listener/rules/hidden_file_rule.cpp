#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/hidden_file_rule.h"

#include <fcntl.h>
#include <sys/syscall.h>

#include <boost/asio/basic_seq_packet_socket.hpp>
#include <boost/sml.hpp>
#include <regex>

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
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());

            bool id_and_arg_match = (syscall_event.id == SYS_creat ||
                                     (syscall_event.id == SYS_open &&
                                      (syscall_event.args[1]) & O_CREAT) ||
                                     (syscall_event.id == SYS_openat &&
                                      (syscall_event.args[2]) & O_CREAT) ||
                                     syscall_event.id == SYS_openat2);
            if (!id_and_arg_match) {
                continue;
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
                case SYS_rename:
                case SYS_renameat:
                case SYS_renameat2:
                    path = std::get<RenameSyscallAdditionalData>(
                               syscall_event.additional_data)
                               .new_path.value_or("");
                    break;
                default:
                    continue;
            }

            std::regex re("/\\..*");
            if (std::regex_search(path, re)) {
                return 30;
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t HiddenFileRule::event_seq_size_hint() { return 1; }
}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
