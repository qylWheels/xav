#include "xavcore/protection/hips/monitor/hips_monitor.h"

#include <outcome/success_failure.hpp>

#include "hips_monitor.skel.h"

namespace xavcore {
HipsMonitor::HipsMonitor(spdlog::logger& logger) : logger_(&logger) {
    this->skel_ = hips_monitor_bpf::open_and_load();
    if (!this->skel_) {
        throw std::runtime_error(
            "Failed to open and load HIPS monitor ebpf module");
    }
    this->logger_->info("HIPS monitor ebpf module loaded");
}

HipsMonitor::~HipsMonitor() {
    if (this->status_ == Status::Running) {
        (void)this->stop();
    }
    hips_monitor_bpf::destroy(this->skel_);
    this->logger_->info("HIPS monitor ebpf module destroyed");
}

outcome::result<void> HipsMonitor::start() {
    if (this->status_ == Status::Running) {
        return outcome::success();
    }

    int ret = hips_monitor_bpf::attach(this->skel_);
    if (ret) {
        return outcome::failure(std::make_error_code(std::errc::io_error));
    }

    // Start monitoring in a separate thread.
    this->monitor_thread_ = std::jthread([this](std::stop_token stop) {
        while (!stop.stop_requested()) {
        }
    });

    this->status_ = Status::Running;

    return outcome::success();
}

outcome::result<void> HipsMonitor::stop() {
    if (this->status_ == Status::Stopped) {
        return outcome::success();
    }

    this->monitor_thread_.request_stop();
    this->monitor_thread_.join();

    hips_monitor_bpf::detach(this->skel_);

    this->status_ = Status::Stopped;

    return outcome::success();
}

int HipsMonitor::event_callback(void* ctx, void* data, std::size_t size) {
    return 0;
}
}  // namespace xavcore
