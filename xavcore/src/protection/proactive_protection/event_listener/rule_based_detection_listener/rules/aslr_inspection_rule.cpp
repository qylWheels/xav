#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rules/aslr_inspection_rule.h"

#include <sys/syscall.h>

#include <cstdlib>
#include <iostream>
#include <regex>
#include <system_error>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
namespace rule_based_detection_listener_rules {
ASLRInspectionRule::ASLRInspectionRule() = default;

ASLRInspectionRule::~ASLRInspectionRule() = default;

std::string ASLRInspectionRule::name() { return "aslr_inspection_rule"; }

std::string ASLRInspectionRule::description() {
    return "A rule to detect ASLR inspection";
}

outcome::result<std::uint8_t> ASLRInspectionRule::apply(
    std::span<std::reference_wrapper<IEvent>> event_seq) {
    for (const auto event : event_seq) {
        try {
            const auto& syscall_event =
                dynamic_cast<const SyscallEvent&>(event.get());

            bool id_match =
                (syscall_event.id == SYS_open ||
                 syscall_event.id == SYS_openat ||
                 syscall_event.id == SYS_openat2 ||
                 syscall_event.id == SYS_read || syscall_event.id == SYS_write);
            if (!id_match) {
                continue;
            }

            std::string path;
            try {
                switch (syscall_event.id) {
                    case SYS_open: {
                        path = std::get<OpenSyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .path.value();
                        break;
                    }
                    case SYS_openat: {
                        path = std::get<OpenatSyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .path.value();
                        break;
                    }
                    case SYS_openat2: {
                        path = std::get<Openat2SyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .path.value();
                        break;
                    }
                    case SYS_read: {
                        path = std::get<ReadSyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .fd_path.value();
                        break;
                    }
                    case SYS_write: {
                        path = std::get<WriteSyscallAdditionalData>(
                                   syscall_event.additional_data)
                                   .fd_path.value();
                        break;
                    }
                    default: {
                        std::abort();  // Unreachable.
                    }
                }
            } catch (...) {
                continue;
            }

            if (path == "/proc/sys/kernel/randomize_va_space") {
                std::cout << "ASLR inspection detected" << std::endl;
                return 20;
            }
        } catch (...) {
            continue;
        }
    }
    return 0;
}

std::size_t ASLRInspectionRule::event_seq_size_hint() { return 1; }

outcome::result<void> ASLRInspectionRule::push_event(IEvent& event) {
    try {
        const auto& syscall_event = dynamic_cast<const SyscallEvent&>(event);

        bool id_match =
            (syscall_event.id == SYS_open || syscall_event.id == SYS_openat ||
             syscall_event.id == SYS_openat2 || syscall_event.id == SYS_read ||
             syscall_event.id == SYS_write);
        if (!id_match) {
            return outcome::success();
        }

        std::string path;
        switch (syscall_event.id) {
            case SYS_open: {
                path = std::get<OpenSyscallAdditionalData>(
                           syscall_event.additional_data)
                           .path.value();
                break;
            }
            case SYS_openat: {
                path = std::get<OpenatSyscallAdditionalData>(
                           syscall_event.additional_data)
                           .path.value();
                break;
            }
            case SYS_openat2: {
                path = std::get<Openat2SyscallAdditionalData>(
                           syscall_event.additional_data)
                           .path.value();
                break;
            }
            case SYS_read: {
                path = std::get<ReadSyscallAdditionalData>(
                           syscall_event.additional_data)
                           .fd_path.value();
                break;
            }
            case SYS_write: {
                path = std::get<WriteSyscallAdditionalData>(
                           syscall_event.additional_data)
                           .fd_path.value();
                break;
            }
            default: {
                std::abort();  // Unreachable.
            }
        }

        std::regex re("/proc/sys/kernel/randomize_va_space");
        if (std::regex_search(path, re)) {
            for (auto& [cbid, cb] : this->callbacks_on_warning_) {
                auto info = ASLRInspectionRuleWarningInfo{};
                cb(info);
            }
        }
    } catch (...) {
        // Ignore.
    }
    return outcome::success();
}

outcome::result<void> ASLRInspectionRule::register_warning_callback(
    int cbid, std::function<void(IRuleWarningInfo&)> cb) {
    if (this->callbacks_on_warning_.find(cbid) !=
        this->callbacks_on_warning_.end()) {
        return std::errc::invalid_argument;
    }
    this->callbacks_on_warning_[cbid] = cb;
    return outcome::success();
}

outcome::result<void> ASLRInspectionRule::unregister_warning_callback(
    int cbid) {
    this->callbacks_on_warning_.erase(cbid);
    return outcome::success();
}

}  // namespace rule_based_detection_listener_rules
}  // namespace xavcore
