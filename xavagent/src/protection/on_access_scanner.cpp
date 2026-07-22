#include "xavagent/protection/on_access_scanner.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/fanotify.h>
#include <unistd.h>

#include <ranges>
#include <stdexcept>

#include "xavagent/global_context.h"

#define BUFSIZE (8 * 1024)  // 8KB

namespace xavagent {
OnAccessScanner::OnAccessScanner()
    : scanned_object_count_(0), blocked_object_count_(0) {
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
                    // Use the exact hash engine first.
                    const auto result = GlobalContext::get_global_context()
                                            .exact_hash_engine()
                                            .scan(std::string{path});
                    if (result.has_value()) {
                        const auto result_value = result.value();
                        resp.response = FAN_DENY;
                        this->blocked_object_count_++;
                    } else {
                        // If the exact hash engine does not detect any malware,
                        // use the static heuristic engine.
                        auto result_from_heur_engine_noerr_nonull =
                            GlobalContext::get_global_context()
                                .static_heur_engine_manager()
                                .scan(path) |
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
    int ret;

    ret = fanotify_mark(this->fanfd_, FAN_MARK_REMOVE | FAN_MARK_FILESYSTEM,
                        FAN_OPEN_EXEC_PERM, AT_FDCWD, "/");
    if (ret < 0) {
        throw std::runtime_error("Remove fanotify mark failed");
    }
}
}  // namespace xavagent
