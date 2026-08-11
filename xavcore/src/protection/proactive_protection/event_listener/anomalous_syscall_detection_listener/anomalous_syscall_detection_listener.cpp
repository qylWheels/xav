#include "xavcore/protection/proactive_protection/event_listener/anomalous_syscall_detection_listener/anomalous_syscall_detection_listener.h"

#include <spdlog/logger.h>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
AnomalousSyscallDetectionListener::AnomalousSyscallDetectionListener(
    spdlog::logger &logger)
    : logger_(&logger) {};

AnomalousSyscallDetectionListener::~AnomalousSyscallDetectionListener() =
    default;

bool AnomalousSyscallDetectionListener::is_accept(const IEvent &event) {
    return typeid(event) == typeid(SyscallEvent);
}

outcome::result<void> AnomalousSyscallDetectionListener::accept(
    const IEvent &event) {
    this->logger_->info("Accepting event");

    return outcome::success();
}

}  // namespace xavcore
