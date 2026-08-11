#pragma once

#include <spdlog/logger.h>

#include <mlpack.hpp>

#include "xavcore/protection/proactive_protection/behavior_monitor.h"

namespace xavcore {
class AnomalousSyscallDetectionListener : public IEventListener {
public:
    AnomalousSyscallDetectionListener(spdlog::logger &logger);
    ~AnomalousSyscallDetectionListener();
    AnomalousSyscallDetectionListener(
        const AnomalousSyscallDetectionListener &) = delete;
    AnomalousSyscallDetectionListener &operator=(
        const AnomalousSyscallDetectionListener &) = delete;

    AnomalousSyscallDetectionListener(AnomalousSyscallDetectionListener &&) =
        delete;
    AnomalousSyscallDetectionListener &operator=(
        AnomalousSyscallDetectionListener &&) = delete;

public:
    virtual bool is_accept(const IEvent &event) override;
    virtual outcome::result<void> accept(const IEvent &event) override;

private:
    spdlog::logger *logger_;
    arma::mat training_set_;
    mlpack::KNN knn_;
};
}  // namespace xavcore
