#include "xavcore/protection/proactive_protection/event_listener/anomalous_syscall_detection_listener/anomalous_syscall_detection_listener.h"

#include <spdlog/logger.h>

#include <armadillo>
#include <format>
#include <mlpack.hpp>
#include <ostream>
#include <outcome/success_failure.hpp>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event.h"

namespace xavcore {
AnomalousSyscallDetectionListener::AnomalousSyscallDetectionListener(
    spdlog::logger &logger)
    : logger_(&logger), training_set_(8, 1) {};

AnomalousSyscallDetectionListener::~AnomalousSyscallDetectionListener() =
    default;

bool AnomalousSyscallDetectionListener::is_accept(const IEvent &event) {
    return typeid(event) == typeid(SyscallEvent);
}

outcome::result<void> AnomalousSyscallDetectionListener::accept(
    const IEvent &event) {
    auto &syscall_event = dynamic_cast<const SyscallEvent &>(event);
    if (syscall_event.args.empty()) {
        return outcome::success();
    }

    arma::vec v{(double)syscall_event.id,      (double)syscall_event.args[0],
                (double)syscall_event.args[1], (double)syscall_event.args[2],
                (double)syscall_event.args[3], (double)syscall_event.args[4],
                (double)syscall_event.args[5], (double)syscall_event.ret};
    this->training_set_ = arma::join_horiz(this->training_set_, v);

    static int i = 0;
    i++;
    if (i % 1000 == 0) {
        std::cout << std::format("\rAdd {} syscall to training set", i)
                  << std::flush;
    }

    return outcome::success();
}

}  // namespace xavcore
