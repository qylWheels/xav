#include "xavcore/protection/on_access_scanning/on_access_scanner.h"

#include <fcntl.h>
#include <limits.h>
#include <linux/fanotify.h>
#include <sys/fanotify.h>
#include <unistd.h>

#include <algorithm>
#include <outcome/success_failure.hpp>
#include <ranges>
#include <stdexcept>
#include <stop_token>
#include <system_error>
#include <thread>

#include "xavcore/scan/scan_interfaces.h"

#define BUFSIZE (8 * 1024)  // 8KB

namespace xavcore {
OnAccessScanner::OnAccessScanner(spdlog::logger& logger,
                                 IScanStrategy& scan_strategy,
                                 utils::cache::Cache& cache)
    : logger_(&logger),
      scan_strategy_(&scan_strategy),
      status_(Status::Stopped),
      cache_(&cache),
      scanned_object_count_(0),
      blocked_object_count_(0) {
    // Initialize the fanotify descriptor.
    this->fanfd_ =
        fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE,
                      O_RDONLY | O_LARGEFILE);
    if (this->fanfd_ < 0) {
        throw std::runtime_error("fanotify_init failed");
    }

    // Allocate buffer for reading fanotify events.
    this->buf_ = new char[BUFSIZE];
}

OnAccessScanner::~OnAccessScanner() {
    (void)this->stop_monitoring();
    close(this->fanfd_);
    delete[] this->buf_;
    this->buf_ = nullptr;
}

outcome::result<void> OnAccessScanner::start_monitoring() {
    if (this->status_ == Status::Running) {
        return outcome::success();
    }

    int ret;

    // Mark the root directory for monitoring.
    ret = fanotify_mark(this->fanfd_, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                        FAN_OPEN_EXEC_PERM, AT_FDCWD, "/");
    if (ret < 0) {
        return outcome::failure(std::error_code(ret, std::system_category()));
    }

    this->monitoring_thread_ =
        std::jthread([this](std::stop_token st) -> outcome::result<void> {
            // Poll and process fanotify events.
            while (!st.stop_requested()) {
                ssize_t len = read(this->fanfd_, this->buf_, BUFSIZE);
                if (len <= 0) continue;

                struct fanotify_event_metadata* metadata =
                    reinterpret_cast<fanotify_event_metadata*>(this->buf_);

                while (FAN_EVENT_OK(metadata, len)) {
                    if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                        return outcome::failure(std::errc::io_error);
                    }

                    if (metadata->fd < 0 || metadata->fd == FAN_NOFD) {
                        metadata = FAN_EVENT_NEXT(metadata, len);
                        continue;
                    }

                    std::string fdpath =
                        std::format("/proc/self/fd/{}", metadata->fd);

                    char path[PATH_MAX + 1] = {0};
                    ssize_t path_len =
                        readlink(fdpath.c_str(), path, sizeof(path) - 1);

                    // TODO: Handle the case where we can't read the path.
                    // I.e. implement scan function on fd.
                    struct fanotify_response resp = {.fd = metadata->fd};

                    if (path_len < 0) {
                        resp.response = FAN_ALLOW;
                        ::write(metadata->fd, &resp, sizeof(resp));
                        ::close(metadata->fd);
                        continue;
                    }

                    bool cache_hit = false;

                    // Lookup the cache first.
                    auto info = this->cache_->get(types::FileFingerprint(path));
                    if (info.has_value()) {  // Cache hit.
                        cache_hit = true;
                        if (info.value().has_value()) {
                            resp.response = FAN_DENY;
                            for (auto& listener : this->event_listeners_) {
                                listener->on_event(path, info.value().value());
                            }
                        } else {
                            resp.response = FAN_ALLOW;
                        }
                    } else {  // Cache miss.
                        auto result = this->scan_strategy_->scan(path);
                        if (result.has_value()) {
                            auto valid_result = std::ranges::filter_view(
                                result.value(), [](const auto& r) {
                                    return r.has_value() &&
                                           r.value().has_value();
                                });
                            auto valid_result_mapped =
                                std::ranges::transform_view(
                                    valid_result, [](const auto& r) {
                                        return r.value().value();
                                    });
                            auto alarm = !valid_result_mapped.empty();
                            if (alarm) {
                                resp.response = FAN_DENY;
                                this->blocked_object_count_++;
                                auto most_likely = std::ranges::max(
                                    valid_result_mapped,
                                    [](const auto& a, const auto& b) {
                                        return a.second.likelihood >
                                               b.second.likelihood;
                                    });

                                // Cache the result.
                                this->cache_->add(types::FileFingerprint(path),
                                                  most_likely.second);

                                for (auto& listener : this->event_listeners_) {
                                    listener->on_event(most_likely.first,
                                                       most_likely.second);
                                }
                            } else {
                                resp.response = FAN_ALLOW;

                                // Cache the result.
                                this->cache_->add(types::FileFingerprint(path),
                                                  std::nullopt);
                            }
                        } else {  // Scan result is an error.
                            resp.response = FAN_ALLOW;

                            // DON'T CACHE THE RESULT!
                            // Because the scan result is an error!
                        }
                    }

                    this->scanned_object_count_++;

                    ::write(this->fanfd_, &resp, sizeof(resp));
                    ::close(metadata->fd);

                    metadata = FAN_EVENT_NEXT(metadata, len);
                }
            }
            return outcome::success();
        });

    this->status_ = Status::Running;

    return outcome::success();
}

outcome::result<void> OnAccessScanner::stop_monitoring() {
    if (this->status_ == Status::Stopped) {
        return outcome::success();
    }

    int ret;

    this->monitoring_thread_.request_stop();
    this->monitoring_thread_.join();

    ret = fanotify_mark(this->fanfd_, FAN_MARK_REMOVE | FAN_MARK_FILESYSTEM,
                        FAN_OPEN_EXEC_PERM, AT_FDCWD, "/");
    if (ret < 0) {
        return outcome::failure(std::error_code(ret, std::system_category()));
    }

    this->status_ = Status::Stopped;

    return outcome::success();
}

void OnAccessScanner::set_scan_strategy(IScanStrategy& scan_strategy) {
    this->scan_strategy_ = &scan_strategy;
}
IScanStrategy* OnAccessScanner::get_scan_strategy() const {
    return this->scan_strategy_;
}

void OnAccessScanner::add_event_listener(
    IOnAccessScannerEventListener& listener) {
    this->event_listeners_.insert(&listener);
}

void OnAccessScanner::remove_event_listener(
    IOnAccessScannerEventListener& listener) {
    this->event_listeners_.erase(&listener);
}
}  // namespace xavcore
