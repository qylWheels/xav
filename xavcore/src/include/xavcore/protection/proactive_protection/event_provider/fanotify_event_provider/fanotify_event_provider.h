#pragma once

#include <linux/fanotify.h>
#include <spdlog/logger.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <unordered_set>

#include "xavcore/protection/proactive_protection/behavior_monitor.h"
#include "xavcore/protection/process_status_viewer.h"

namespace xavcore {
class FanotifyEventProvider : public IEventProvider {
public:
    FanotifyEventProvider(ProcessStatusViewer& process_status_viewer);
    ~FanotifyEventProvider();
    FanotifyEventProvider(const FanotifyEventProvider&) = delete;
    FanotifyEventProvider& operator=(const FanotifyEventProvider&) = delete;
    FanotifyEventProvider(FanotifyEventProvider&&) = delete;
    FanotifyEventProvider& operator=(FanotifyEventProvider&&) = delete;

public:
    virtual outcome::result<void> start() override;
    virtual outcome::result<void> stop() override;
    virtual std::uint64_t lost_event_count() override;
    virtual outcome::result<void> listener_register(
        IEventListener& listener) override;
    virtual outcome::result<void> listener_unregister(
        IEventListener& listener) override;

private:
    std::optional<std::string> get_path_from_dfid_name_record(
        fanotify_event_info_fid* dfid_name_record);

private:
    enum class Status {
        Stopped,
        Running,
    };

private:
    int fanfd_;
    char* fanbuf_;
    int mount_fd_;
    std::shared_ptr<spdlog::logger> logger_;
    std::unordered_set<IEventListener*> listeners_;
    Status status_;
    std::jthread monitoring_thread_;
    ProcessStatusViewer* process_status_viewer_;
};
}  // namespace xavcore
