#include "behavior_monitor.h"

#include <fcntl.h>
#include <limits.h>
#include <linux/fanotify.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <sys/fanotify.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <ranges>
#include <stdexcept>

#include "spdlog/common.h"
#include "xavagent/edr/event.h"

#define BUFSIZE (4 * 1024)  // 4KB

namespace xavagent {
BehaviorMonitor::BehaviorMonitor()
    : total_event_count_(0), suspicious_event_count_(0) {
    // Initialize logger.
    this->logger_ = spdlog::stdout_color_mt("behavior_monitor");
    this->logger_->set_level(spdlog::level::info);

    // Initialize the fanotify descriptor.
    this->fanfd_ =
        fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE |
                          FAN_REPORT_DFID_NAME_TARGET,
                      O_RDONLY | O_LARGEFILE);
    if (this->fanfd_ < 0) {
        throw std::runtime_error(
            std::format("fanotify_init failed: {} ({}) at {}:{}", errno,
                        std::strerror(errno), __FILE__, __LINE__));
    }

    // Allocate buffer for reading fanotify events.
    this->fanbuf_ = new char[BUFSIZE];

    // Open mount fd
    this->mount_fd_ = open("/", O_DIRECTORY | O_RDONLY);
    if (this->mount_fd_ < 0) {
        throw std::runtime_error(std::format("open / failed: {} ({}) at {}:{}",
                                             errno, std::strerror(errno),
                                             __FILE__, __LINE__));
    }
}

BehaviorMonitor::~BehaviorMonitor() {
    close(this->fanfd_);
    delete[] this->fanbuf_;
    this->fanbuf_ = nullptr;
    close(this->mount_fd_);
}

void BehaviorMonitor::start_monitoring() {
    // Mark the root directory for monitoring.
    // TODO: Monitor other type of event: attribute change.
    if (fanotify_mark(this->fanfd_, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                      FAN_CREATE | FAN_DELETE | FAN_ACCESS | FAN_MODIFY |
                          FAN_RENAME | FAN_ATTRIB | FAN_ONDIR,
                      AT_FDCWD, "/") < 0) {
        throw std::runtime_error(
            std::format("fanotify_mark failed: {} ({}) at {}:{}", errno,
                        std::strerror(errno), __FILE__, __LINE__));
    }

    // Poll and process fanotify events.
    while (true) {
        ssize_t len = read(this->fanfd_, this->fanbuf_, BUFSIZE);
        if (len <= 0) continue;

        // Ignore self event.
        fanotify_event_metadata *metadata =
            reinterpret_cast<fanotify_event_metadata *>(this->fanbuf_);
        if (metadata->pid == getpid()) {
            continue;
        }

        fanotify_event_info_header *additional_infos_hdr = nullptr;
        std::size_t additional_infos_len = 0;
        fanotify_event_info_fid *dfid_name_record = nullptr;
        fanotify_event_info_fid *fid_record = nullptr;

        // For rename event.
        fanotify_event_info_fid *old_dfid_name_record = nullptr;
        fanotify_event_info_fid *new_dfid_name_record = nullptr;

        // It might be multiple events in one read.
        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                throw std::runtime_error(
                    std::format("fanotify metadata version mismatch: {} != {}",
                                metadata->vers, FANOTIFY_METADATA_VERSION));
            }

            fid_record = nullptr;
            dfid_name_record = nullptr;
            old_dfid_name_record = nullptr;
            new_dfid_name_record = nullptr;
            additional_infos_hdr =
                (struct fanotify_event_info_header *)(metadata + 1);
            additional_infos_len = metadata->event_len - sizeof(*metadata);

            // Handle additional information.
            while (additional_infos_len > 0) {
                switch (additional_infos_hdr->info_type) {
                    case FAN_EVENT_INFO_TYPE_FID:
                        fid_record = (struct fanotify_event_info_fid *)
                            additional_infos_hdr;
                        break;
                    case FAN_EVENT_INFO_TYPE_DFID_NAME:
                        dfid_name_record = (struct fanotify_event_info_fid *)
                            additional_infos_hdr;
                        break;
                    case FAN_EVENT_INFO_TYPE_OLD_DFID_NAME:
                        old_dfid_name_record =
                            (struct fanotify_event_info_fid *)
                                additional_infos_hdr;
                        break;
                    case FAN_EVENT_INFO_TYPE_NEW_DFID_NAME:
                        new_dfid_name_record =
                            (struct fanotify_event_info_fid *)
                                additional_infos_hdr;
                        break;
                    default:
                        break;
                }
                additional_infos_len -= additional_infos_hdr->len;
                additional_infos_hdr = (struct fanotify_event_info_header
                                            *)((char *)additional_infos_hdr +
                                               additional_infos_hdr->len);
            }

            // Get information of the process which accessed the file.
            Process proc = {
                .pid = metadata->pid,
                .ppid = this->get_proc_ppid(metadata->pid),
                .start_time_tick =
                    this->get_proc_start_time_tick(metadata->pid),
                .exe_path = this->get_proc_exe_path(metadata->pid),
                .cmdline = this->get_proc_cmdline(metadata->pid),
            };

            // Generate event.
            FileEvent event = {
                .proc = proc,
            };

            if (old_dfid_name_record == nullptr &&
                new_dfid_name_record == nullptr) {  // NOT move event.
                auto result =
                    this->get_path_from_dfid_name_record(dfid_name_record);
                event.path1 = result.has_value() ? result.value() : "";

                // Get file status.
                try {
                    event.stat1 = std::filesystem::status(event.path1);
                } catch (...) {
                    event.stat1 = std::nullopt;
                }
            } else {  // IS move event.
                auto result1 =
                    this->get_path_from_dfid_name_record(old_dfid_name_record);
                event.path1 = result1.has_value() ? result1.value() : "";
                auto result2 =
                    this->get_path_from_dfid_name_record(new_dfid_name_record);
                event.path2 = result2.has_value() ? result2.value() : "";

                // Get file status.
                try {
                    event.stat1 = std::filesystem::status(event.path1);
                } catch (...) {
                    event.stat1 = std::nullopt;
                }
                try {
                    event.stat2 = std::filesystem::status(event.path2.value());
                } catch (...) {
                    event.stat2 = std::nullopt;
                }
            }

            // Set event mask.
            if (metadata->mask & FAN_CREATE) {
                event.event_type_mask.set(
                    static_cast<int>(FileEvent::FileEventType::Create), true);
            }
            if (metadata->mask & FAN_DELETE) {
                event.event_type_mask.set(
                    static_cast<int>(FileEvent::FileEventType::Delete), true);
            }
            if (metadata->mask & FAN_ACCESS) {
                event.event_type_mask.set(
                    static_cast<int>(FileEvent::FileEventType::Read), true);
            }
            if (metadata->mask & FAN_MODIFY) {
                event.event_type_mask.set(
                    static_cast<int>(FileEvent::FileEventType::Write), true);
            }
            if (metadata->mask & FAN_RENAME) {
                event.event_type_mask.set(
                    static_cast<int>(FileEvent::FileEventType::Move), true);
            }
            if (metadata->mask & FAN_ATTRIB) {
                event.event_type_mask.set(
                    static_cast<int>(FileEvent::FileEventType::AttributeChange),
                    true);
            }

            // Add event into map.
            this->procs_events_[proc].push_back(event);

            this->total_event_count_++;

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

void BehaviorMonitor::stop_monitoring() {
    // TODO
}

std::optional<std::string> BehaviorMonitor::get_path_from_dfid_name_record(
    fanotify_event_info_fid *dfid_name_record) {
    // Get fd of the directory.
    struct file_handle *dir_handle =
        (struct file_handle *)dfid_name_record->handle;
    int dir_fd = open_by_handle_at(this->mount_fd_, dir_handle, O_RDONLY);
    if (dir_fd == -1) {
        if (errno == ESTALE) {
            this->logger_->log({__FILE__, __LINE__, __FUNCTION__},
                               spdlog::level::info, "ESTALE, skip");
        } else {
            this->logger_->log({__FILE__, __LINE__, __FUNCTION__},
                               spdlog::level::warn,
                               "open_by_handle_at failed: {} ({})", errno,
                               std::strerror(errno));
        }
        return std::nullopt;
    } else {
        std::string dir_path;
        std::optional<std::string> result = std::nullopt;
        try {
            // Get path of the directory.
            dir_path = std::filesystem::read_symlink(
                std::format("/proc/self/fd/{}", dir_fd));
            // Get name of the file which is accessed.
            std::string filename =
                (const char *)(dir_handle->f_handle + dir_handle->handle_bytes);
            result = dir_path + "/" + filename;
        } catch (...) {
            this->logger_->log(
                {__FILE__, __LINE__, __FUNCTION__}, spdlog::level::warn,
                "get file path failed: {} ({})", errno, std::strerror(errno));
        }
        close(dir_fd);
        return result;
    }
}

std::optional<int> BehaviorMonitor::get_proc_ppid(int pid) {
    try {
        auto ppid_str = this->get_proc_raw_stat(pid, 18);
        if (ppid_str.has_value()) {
            return std::stoi(ppid_str.value());
        }
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<unsigned long long> BehaviorMonitor::get_proc_start_time_tick(
    int pid) {
    try {
        auto start_time_tick_str = this->get_proc_raw_stat(pid, 22);
        if (start_time_tick_str.has_value()) {
            return std::stoull(start_time_tick_str.value());
        }
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::string> BehaviorMonitor::get_proc_exe_path(int pid) {
    try {
        std::string exe_path = std::format("/proc/{}/exe", pid);
        std::string exe_path_str;
        exe_path_str = std::filesystem::read_symlink(exe_path);
        return exe_path_str;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::string> BehaviorMonitor::get_proc_cmdline(int pid) {
    try {
        std::string cmdline_path = std::format("/proc/{}/cmdline", pid);
        std::ifstream cmdline_file(cmdline_path);
        std::vector<char> cmdline_content{
            std::istreambuf_iterator<char>(cmdline_file),
            std::istreambuf_iterator<char>()};
        std::replace_if(
            cmdline_content.begin(), cmdline_content.end(),
            [](char c) { return c == '\0'; }, ' ');
        return std::string(cmdline_content.begin(), cmdline_content.end());
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::string> BehaviorMonitor::get_proc_raw_stat(int pid, int n) {
    try {
        std::string stat_path = std::format("/proc/{}/stat", pid);
        std::ifstream stat_file(stat_path);
        std::string stat_content{std::istreambuf_iterator<char>(stat_file),
                                 std::istreambuf_iterator<char>()};
        auto take_view = stat_content | std::views::split(' ') |
                         std::views::drop(n - 1) | std::views::take(1);
        auto value = *take_view.begin();
        std::string value_str{value.begin(), value.end()};
        return value_str;
    } catch (...) {
        return std::nullopt;
    }
}
}  // namespace xavagent
