#include "xavcore/protection/proactive_protection/event_provider/process_lifecycle_event_provider/process_lifecycle_event_provider.h"

#include <chrono>

#include "xavcore/protection/proactive_protection/event_provider/process_lifecycle_event_provider/raw_process_lifecycle_event.h"

namespace xavcore {
ProcessLifecycleEventProvider::ProcessLifecycleEventProvider(
    spdlog::logger& logger)
    : logger_(&logger), status_(Status::Stopped) {
    this->skel_ = process_lifecycle_event_provider_bpf::open_and_load();
    if (!this->skel_) {
        throw std::runtime_error("Failed to open and load BPF skeleton");
    }
    this->logger_->info("Process lifecycle event provider loaded");
}

ProcessLifecycleEventProvider::~ProcessLifecycleEventProvider() {
    if (this->status_ == Status::Running) {
        (void)this->stop();
    }
    process_lifecycle_event_provider_bpf::destroy(this->skel_);
}

outcome::result<void> ProcessLifecycleEventProvider::start() {
    if (this->status_ != Status::Stopped) {
        return outcome::failure(
            std::make_error_code(std::errc::device_or_resource_busy));
    }

    int ret = process_lifecycle_event_provider_bpf::attach(this->skel_);
    if (ret) {
        return outcome::failure(std::make_error_code(std::errc::io_error));
    }
    this->rb_ = ring_buffer__new(bpf_map__fd(this->skel_->maps.rb),
                                 ProcessLifecycleEventProvider::event_callback,
                                 this, nullptr);
    if (!this->rb_) {
        return outcome::failure(std::make_error_code(std::errc::io_error));
    }

    // Start monitoring in a separate thread.
    this->monitor_thread_ = std::jthread([this](std::stop_token stop) {
        while (!stop.stop_requested()) {
            int err = ring_buffer__poll(this->rb_, 1000);
            if (err < 0) {
                this->logger_->warn("Failed to poll ring buffer");
            }
        }
    });

    this->status_ = Status::Running;

    return outcome::success();
}

outcome::result<void> ProcessLifecycleEventProvider::stop() {
    if (this->status_ != Status::Running) {
        return outcome::failure(
            std::make_error_code(std::errc::no_such_device_or_address));
    }

    this->monitor_thread_.request_stop();
    this->monitor_thread_.join();

    ring_buffer__free(this->rb_);
    this->rb_ = nullptr;

    process_lifecycle_event_provider_bpf::detach(this->skel_);

    this->status_ = Status::Stopped;

    return outcome::success();
}

std::uint64_t ProcessLifecycleEventProvider::lost_event_count() {
    return this->lost_event_count_;
}

outcome::result<void> ProcessLifecycleEventProvider::listener_register(
    IEventListener& listener) {
    if (this->listeners_.find(&listener) != this->listeners_.end()) {
        return outcome::failure(std::make_error_code(std::errc::file_exists));
    }
    this->listeners_.insert(&listener);
    return outcome::success();
}

outcome::result<void> ProcessLifecycleEventProvider::listener_unregister(
    IEventListener& listener) {
    if (this->listeners_.find(&listener) == this->listeners_.end()) {
        return outcome::failure(
            std::make_error_code(std::errc::no_such_file_or_directory));
    }
    this->listeners_.erase(&listener);
    return outcome::success();
}

int ProcessLifecycleEventProvider::event_callback(void* ctx, void* data,
                                                  std::size_t size) {
    ProcessLifecycleEventProvider* self =
        static_cast<ProcessLifecycleEventProvider*>(ctx);
    RawProcessLifecycleEvent* raw_event =
        static_cast<RawProcessLifecycleEvent*>(data);

    switch (raw_event->tag) {
        case 0: {
            // Process create event
            ProcessCreateEvent e(std::chrono::system_clock::now(),
                                 raw_event->u.create.pid);
            for (auto& listener : self->listeners_) {
                if (listener->is_accept(e)) {
                    (void)listener->accept(e);
                }
            }
            break;
        }
        case 1: {
            // Process exit event
            ProcessExitEvent e(std::chrono::system_clock::now(),
                               raw_event->u.exit.pid);
            for (auto& listener : self->listeners_) {
                if (listener->is_accept(e)) {
                    (void)listener->accept(e);
                }
            }
            break;
        }
        default: {
            self->logger_->warn("Unknown process lifecycle event tag: {}",
                                raw_event->tag);
            break;
        }
    }

    return 0;
}
}  // namespace xavcore
