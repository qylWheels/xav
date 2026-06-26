#include "execution_monitor.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/fanotify.h>
#include <unistd.h>

#include <format>

#define BUFSIZE (1 * 1024 * 1024)  // 1MB

namespace xav {
ExecutionMonitor::ExecutionMonitor() {
    // Initialize the fanotify descriptor.
    this->fanfd_ = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC |
                                     FAN_UNLIMITED_QUEUE | FAN_REPORT_PIDFD,
                                 O_RDONLY | O_LARGEFILE);
    if (this->fanfd_ < 0) {
        perror("fanotify_init failed");
        exit(1);
    }

    // Mark the root directory for monitoring.
    if (fanotify_mark(this->fanfd_, FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_OPEN_EXEC_PERM, AT_FDCWD, "/") < 0) {
        perror("fanotify_mark failed");
        exit(1);
    }

    // Allocate buffer for reading fanotify events.
    this->buf_ = new char[BUFSIZE];
    if (this->buf_ == nullptr) {
        perror("malloc failed");
        exit(1);
    }
}

ExecutionMonitor::~ExecutionMonitor() {
    close(this->fanfd_);
    delete[] this->buf_;
    this->buf_ = nullptr;
}

void ExecutionMonitor::start_monitoring() {
    // Poll and process fanotify events.
    while (true) {
        ssize_t len = read(this->fanfd_, this->buf_, BUFSIZE);
        if (len <= 0) continue;

        struct fanotify_event_metadata *metadata =
            reinterpret_cast<fanotify_event_metadata *>(this->buf_);

        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                perror("fanotify metadata version mismatch");
                exit(1);
            }

            if (metadata->fd >= 0) {
                std::string fdpath =
                    std::format("/proc/self/fd/{}", metadata->fd);

                char path[PATH_MAX + 1] = {0};
                ssize_t path_len =
                    readlink(fdpath.c_str(), path, sizeof(path) - 1);

                if (path_len > 0) {
                    struct fanotify_response resp = {.fd = metadata->fd};
                    const auto result =
                        this->exact_hash_engine_.scan(std::string{path});
                    if (result.has_value()) {
                        printf("[BLOCK] %s\n", path);
                        const auto result_value = result.value();
                        std::cout
                            << std::format(
                                   "<MalwareBazaar><ExactHash> Generic.{}",
                                   result_value.variant())
                            << std::endl;
                        resp.response = FAN_DENY;
                    } else {
                        // printf("[ALLOW] %s\n", path);
                        resp.response = FAN_ALLOW;
                    }

                    write(this->fanfd_, &resp, sizeof(resp));
                }

                close(metadata->fd);
            }

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

void ExecutionMonitor::stop_monitoring() {
    // TODO
}
}  // namespace xav
