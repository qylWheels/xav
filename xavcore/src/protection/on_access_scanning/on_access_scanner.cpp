#include "xavcore/protection/on_access_scanning/on_access_scanner.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/fanotify.h>
#include <unistd.h>

#include <algorithm>
#include <stdexcept>

#include "xavcore/scan/scan_interfaces.h"

#define BUFSIZE (8 * 1024)  // 8KB

namespace xavcore {
OnAccessScanner::OnAccessScanner(IScanStrategy& scan_strategy)
    : scan_strategy_(&scan_strategy),
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
    close(this->fanfd_);
    delete[] this->buf_;
    this->buf_ = nullptr;
}

void OnAccessScanner::start_monitoring() {
    int ret;

    // Mark the root directory for monitoring.
    ret = fanotify_mark(this->fanfd_, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                        FAN_OPEN_EXEC_PERM, AT_FDCWD, "/");
    if (ret < 0) {
        throw std::runtime_error("Add fanotify mark failed");
    }

    // Poll and process fanotify events.
    while (true) {
        ssize_t len = read(this->fanfd_, this->buf_, BUFSIZE);
        if (len <= 0) continue;

        struct fanotify_event_metadata* metadata =
            reinterpret_cast<fanotify_event_metadata*>(this->buf_);

        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                throw std::runtime_error("fanotify metadata version mismatch");
            }

            if (metadata->fd >= 0) {
                std::string fdpath =
                    std::format("/proc/self/fd/{}", metadata->fd);

                char path[PATH_MAX + 1] = {0};
                ssize_t path_len =
                    readlink(fdpath.c_str(), path, sizeof(path) - 1);

                // TODO: Handle the case where we can't read the path.
                // I.e. implement scan function on fd.
                if (path_len > 0) {
                    struct fanotify_response resp = {.fd = metadata->fd};

                    // TODO: Report when detected malware.
                    auto result = this->scan_strategy_->scan(path);
                    if (result.has_value()) {
                        auto alarm = std::ranges::any_of(
                            result.value(), [](const auto& r) {
                                return r.has_value() && r.value().has_value();
                            });
                        if (alarm) {
                            resp.response = FAN_DENY;
                            this->blocked_object_count_++;
                        } else {
                            resp.response = FAN_ALLOW;
                        }
                    } else {
                        resp.response = FAN_ALLOW;
                    }

                    this->scanned_object_count_++;

                    write(this->fanfd_, &resp, sizeof(resp));
                }

                close(metadata->fd);
            }

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

void OnAccessScanner::stop_monitoring() {
    int ret;

    ret = fanotify_mark(this->fanfd_, FAN_MARK_REMOVE | FAN_MARK_FILESYSTEM,
                        FAN_OPEN_EXEC_PERM, AT_FDCWD, "/");
    if (ret < 0) {
        throw std::runtime_error("Remove fanotify mark failed");
    }
}

void OnAccessScanner::set_scan_strategy(IScanStrategy& scan_strategy) {
    this->scan_strategy_ = &scan_strategy;
}
IScanStrategy* OnAccessScanner::get_scan_strategy() const {
    return this->scan_strategy_;
}
}  // namespace xavcore
