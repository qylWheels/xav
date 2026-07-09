#include "on_access_scanner.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/fanotify.h>
#include <unistd.h>

#include <format>
#include <memory>
#include <ranges>

#include "xavlib/heuristic/static_heuristic.h"
#include "xavlib/heuristic/yara_static_heuristic_engine.h"

#define BUFSIZE (1 * 1024 * 1024)  // 1MB

namespace xavagent {
OnAccessScanner::OnAccessScanner()
    : scanned_object_count_(0), blocked_object_count_(0) {
    // Initialize the fanotify descriptor.
    this->fanfd_ =
        fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE,
                      O_RDONLY | O_LARGEFILE);
    if (this->fanfd_ < 0) {
        perror("fanotify_init failed");
        exit(1);
    }

    // Mark the root directory for monitoring.
    // FIXME: This should be in start_monitoring().
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

    // Initialize the static heuristic engine manager.
    this->static_heur_engine_manager_.add_engine(
        std::make_unique<xavlib::YaraStaticHeuristicEngine>());
}

OnAccessScanner::~OnAccessScanner() {
    close(this->fanfd_);
    delete[] this->buf_;
    this->buf_ = nullptr;
}

void OnAccessScanner::start_monitoring() {
    // Poll and process fanotify events.
    while (true) {
        ssize_t len = read(this->fanfd_, this->buf_, BUFSIZE);
        if (len <= 0) continue;

        struct fanotify_event_metadata* metadata =
            reinterpret_cast<fanotify_event_metadata*>(this->buf_);

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

                    // TODO: Report when detected malware.
                    // Use the exact hash engine first.
                    const auto result =
                        this->exact_hash_engine_.scan(std::string{path});
                    if (result.has_value()) {
                        const auto result_value = result.value();
                        resp.response = FAN_DENY;
                        this->blocked_object_count_++;
                    } else {
                        // If the exact hash engine does not detect any malware,
                        // use the static heuristic engine.
                        auto result_from_heur_engine_noerr_nonull =
                            this->static_heur_engine_manager_.scan(path) |
                            std::views::filter(
                                [](const auto& r) { return r.has_value(); }) |
                            std::views::transform(
                                [](const auto& r) { return r.value(); }) |
                            std::views::filter(
                                [](const auto& r) { return r.has_value(); }) |
                            std::views::transform(
                                [](const auto& r) { return r.value(); });
                        if (std::ranges::empty(
                                result_from_heur_engine_noerr_nonull)) {
                            resp.response = FAN_ALLOW;
                        } else {
                            resp.response = FAN_DENY;
                            this->blocked_object_count_++;
                        }
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
    // TODO
}
}  // namespace xavagent
