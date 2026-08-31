#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_based_detection_listener.h"

#include <spdlog/spdlog.h>
#include <sys/syscall.h>

#include <algorithm>
#include <cstddef>
#include <regex>
#include <variant>
#include <vector>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
RuleBasedDetectionListener::RuleBasedDetectionListener(spdlog::logger& logger)
    : logger_(&logger) {}

RuleBasedDetectionListener::~RuleBasedDetectionListener() = default;

bool RuleBasedDetectionListener::is_accept(const IEvent& event) {
    try {
        (void)dynamic_cast<const SyscallEvent&>(event);
        return true;
    } catch (...) {
        return false;
    }
}

outcome::result<void> RuleBasedDetectionListener::accept(const IEvent& event) {
    const SyscallEvent& syscall_event =
        dynamic_cast<const SyscallEvent&>(event);
    this->proc_syscall_events_[syscall_event.process].push_back(syscall_event);

    // FIXME: Test print.
    std::regex xavcoretest_regex(".*xavcoretest");
    if (syscall_event.id == SYS_read &&
        std::holds_alternative<ReadSyscallAdditionalData>(
            syscall_event.additional_data)) {
        auto& read_syscall_additional_data =
            std::get<ReadSyscallAdditionalData>(syscall_event.additional_data);
        if (syscall_event.args.empty()) {
            this->logger_->info("read() = {}", syscall_event.ret);
        } else {
            if (read_syscall_additional_data.fd_path.has_value() &&
                std::regex_match(read_syscall_additional_data.fd_path.value(),
                                 xavcoretest_regex)) {
                this->logger_->info(
                    "read({}({}), {:#x}, {}) = {}", syscall_event.args[0],
                    read_syscall_additional_data.fd_path.value_or("<unknown>"),
                    syscall_event.args[1], syscall_event.args[2],
                    syscall_event.ret);
            }
        }
    } else if (syscall_event.id == SYS_write &&
               std::holds_alternative<WriteSyscallAdditionalData>(
                   syscall_event.additional_data)) {
        auto& write_syscall_additional_data =
            std::get<WriteSyscallAdditionalData>(syscall_event.additional_data);
        if (syscall_event.args.empty()) {
            this->logger_->info("write() = {}", syscall_event.ret);
        } else {
            if (write_syscall_additional_data.fd_path.has_value() &&
                std::regex_match(write_syscall_additional_data.fd_path.value(),
                                 xavcoretest_regex)) {
                this->logger_->info(
                    "write({}({}), {:#x}, {}) = {}", syscall_event.args[0],
                    write_syscall_additional_data.fd_path.value_or("<unknown>"),
                    syscall_event.args[1], syscall_event.args[2],
                    syscall_event.ret);
            }
        }
    } else if (syscall_event.id == SYS_open &&
               std::holds_alternative<OpenSyscallAdditionalData>(
                   syscall_event.additional_data)) {
        auto& open_syscall_additional_data =
            std::get<OpenSyscallAdditionalData>(syscall_event.additional_data);
        if (syscall_event.args.empty()) {
            this->logger_->info("open() = {}", syscall_event.ret);
        } else {
            if (open_syscall_additional_data.path.has_value() &&
                std::regex_match(open_syscall_additional_data.path.value(),
                                 xavcoretest_regex)) {
                this->logger_->info(
                    "open({:#x}({}), {}, {}) = {}", syscall_event.args[0],
                    open_syscall_additional_data.path.value_or("<unknown>"),
                    syscall_event.args[1], syscall_event.args[2],
                    syscall_event.ret);
            }
        }
    } else if (syscall_event.id == SYS_openat &&
               std::holds_alternative<OpenatSyscallAdditionalData>(
                   syscall_event.additional_data)) {
        auto& openat_syscall_additional_data =
            std::get<OpenatSyscallAdditionalData>(
                syscall_event.additional_data);
        if (syscall_event.args.empty()) {
            this->logger_->info("openat() = {}", syscall_event.ret);
        } else {
            if (openat_syscall_additional_data.path.has_value() &&
                std::regex_match(openat_syscall_additional_data.path.value(),
                                 xavcoretest_regex)) {
                this->logger_->info(
                    "openat(({}, {:#x})({}), {}) = {}", syscall_event.args[0],
                    syscall_event.args[1],
                    openat_syscall_additional_data.path.value_or("<unknown>"),
                    syscall_event.args[2], syscall_event.ret);
            }
        }
    } else if (syscall_event.id == SYS_openat2 &&
               std::holds_alternative<Openat2SyscallAdditionalData>(
                   syscall_event.additional_data)) {
        auto& openat2_syscall_additional_data =
            std::get<Openat2SyscallAdditionalData>(
                syscall_event.additional_data);
        if (syscall_event.args.empty()) {
            this->logger_->info("openat2() = {}", syscall_event.ret);
        } else {
            if (openat2_syscall_additional_data.path.has_value() &&
                std::regex_match(openat2_syscall_additional_data.path.value(),
                                 xavcoretest_regex)) {
                this->logger_->info(
                    "openat2(({}, {:#x})({}), {}, {}) = {}",
                    syscall_event.args[0], syscall_event.args[1],
                    openat2_syscall_additional_data.path.value_or("<unknown>"),
                    syscall_event.args[2], syscall_event.args[3],
                    syscall_event.ret);
            }
        }
    } else if (syscall_event.id == SYS_close &&
               std::holds_alternative<CloseSyscallAdditionalData>(
                   syscall_event.additional_data)) {
        auto& close_syscall_additional_data =
            std::get<CloseSyscallAdditionalData>(syscall_event.additional_data);
        if (syscall_event.args.empty()) {
            this->logger_->info("close() = {}", syscall_event.ret);
        } else {
            if (close_syscall_additional_data.fd_path.has_value() &&
                std::regex_match(close_syscall_additional_data.fd_path.value(),
                                 xavcoretest_regex)) {
                this->logger_->info(
                    "close({}({})) = {}", syscall_event.args[0],
                    close_syscall_additional_data.fd_path.value_or("<unknown>"),
                    syscall_event.ret);
            }
        }
    } else if (syscall_event.id == SYS_creat &&
               std::holds_alternative<CreatSyscallAdditionalData>(
                   syscall_event.additional_data)) {
        auto& creat_syscall_additional_data =
            std::get<CreatSyscallAdditionalData>(syscall_event.additional_data);
        if (syscall_event.args.empty()) {
            this->logger_->info("creat() = {}", syscall_event.ret);
        } else {
            if (creat_syscall_additional_data.path.has_value() &&
                std::regex_match(creat_syscall_additional_data.path.value(),
                                 xavcoretest_regex)) {
                this->logger_->info(
                    "creat({:#x}({}), {}) = {}", syscall_event.args[0],
                    creat_syscall_additional_data.path.value_or("<unknown>"),
                    syscall_event.args[1], syscall_event.ret);
            }
        }
    } else if (syscall_event.id == SYS_unlink &&
               std::holds_alternative<UnlinkSyscallAdditionalData>(
                   syscall_event.additional_data)) {
        auto& unlink_syscall_additional_data =
            std::get<UnlinkSyscallAdditionalData>(
                syscall_event.additional_data);
        if (syscall_event.args.empty()) {
            this->logger_->info("unlink() = {}", syscall_event.ret);
        } else {
            if (unlink_syscall_additional_data.path.has_value() &&
                std::regex_match(unlink_syscall_additional_data.path.value(),
                                 xavcoretest_regex)) {
                this->logger_->info(
                    "unlink({:#x}({})) = {}", syscall_event.args[0],
                    unlink_syscall_additional_data.path.value_or("<unknown>"),
                    syscall_event.ret);
            }
        }
    } else if ((syscall_event.id == SYS_rename ||
                syscall_event.id == SYS_renameat ||
                syscall_event.id == SYS_renameat2) &&
               std::holds_alternative<RenameSyscallAdditionalData>(
                   syscall_event.additional_data)) {
        auto& rename_syscall_additional_data =
            std::get<RenameSyscallAdditionalData>(
                syscall_event.additional_data);
        if (syscall_event.args.empty()) {
            this->logger_->info("rename() = {}", syscall_event.ret);
        } else {
            bool old_path_match =
                rename_syscall_additional_data.old_path.has_value() &&
                std::regex_match(
                    rename_syscall_additional_data.old_path.value(),
                    xavcoretest_regex);
            bool new_path_match =
                rename_syscall_additional_data.new_path.has_value() &&
                std::regex_match(
                    rename_syscall_additional_data.new_path.value(),
                    xavcoretest_regex);
            if (old_path_match || new_path_match) {
                this->logger_->info(
                    "rename({}, {}) = {}",
                    rename_syscall_additional_data.old_path.value_or(
                        "<unknown>"),
                    rename_syscall_additional_data.new_path.value_or(
                        "<unknown>"),
                    syscall_event.ret);
            }
        }
    }

    // Apply rules.
    for (auto& rule : this->rules_) {
        const auto& proc_syscall_events =
            this->proc_syscall_events_[syscall_event.process];
        std::size_t n = std::min(rule->event_seq_size_hint() * 3,
                                 proc_syscall_events.size());
        std::vector<SyscallEvent> event_slice(proc_syscall_events.end() - n,
                                              proc_syscall_events.end());
        std::vector<std::reference_wrapper<IEvent>> event_ref_slice(
            event_slice.begin(), event_slice.end());
        auto severity = rule->apply(event_ref_slice);
        if (severity.has_error()) {
            this->logger_->error("Error when apply rule");
        } else {
            if (severity.value() > 0) {
                this->logger_->info(
                    "Event sequence severity of {}: {} (Rule {}, Description: "
                    "{})",
                    syscall_event.process.pid, severity.value(), rule->name(),
                    rule->description());
                this->logger_->info("Event count of {}: {}\n",
                                    syscall_event.process.pid,
                                    proc_syscall_events.size());
            }
        }
    }

    return outcome::success();
}

outcome::result<void> RuleBasedDetectionListener::add_rule(
    IRuleBasedDetectionListenerRule& rule) {
    this->rules_.insert(&rule);
    return outcome::success();
}

outcome::result<void> RuleBasedDetectionListener::remove_rule(
    IRuleBasedDetectionListenerRule& rule) {
    this->rules_.erase(&rule);
    return outcome::success();
}

}  // namespace xavcore
