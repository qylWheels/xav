#pragma once

#include <spdlog/spdlog.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include "xavcore/scan/scan_interfaces.h"
#include "xavcore/types/malware_info.h"

namespace xavcore {
enum class ScanStatus {
    Scanning,
    Paused,
    Stopped,
};

class Scanner {
public:
    Scanner(IScanStrategy& scan_strategy);
    ~Scanner();
    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;
    Scanner(Scanner&&) = delete;
    Scanner& operator=(Scanner&&) = delete;

public:
    void scan(const char* path, int nthreads);
    void scan(const std::string& path, int nthreads);
    void scan(const std::filesystem::path& path, int nthreads);

public:
    void set_scan_strategy(IScanStrategy& scan_strategy);
    IScanStrategy* get_scan_strategy();

public:  // Scan information getters.
    std::uint32_t total_file_count() {
        std::unique_lock<std::mutex> lock(this->mutex_);
        auto total_file_count = this->total_file_count_;
        lock.unlock();
        return total_file_count;
    }

    std::uint32_t scanned_file_count() {
        std::unique_lock<std::mutex> lock(this->mutex_);
        auto scanned_file_count = this->scanned_file_count_;
        lock.unlock();
        return scanned_file_count;
    }

    std::vector<std::pair<std::string, types::MalwareInfo>> malware_infos() {
        std::unique_lock<std::mutex> lock(this->mutex_);
        auto malware_infos = this->malware_infos_;
        lock.unlock();
        return malware_infos;
    }

    std::filesystem::path curr_scanning_file() {
        std::unique_lock<std::mutex> lock(this->mutex_);
        auto curr_scanning_file = this->curr_scanning_file_;
        lock.unlock();
        return curr_scanning_file;
    }

    ScanStatus scan_status() {
        std::unique_lock<std::mutex> lock(this->mutex_);
        auto scan_status = this->scan_status_;
        lock.unlock();
        return scan_status;
    }

private:
    void ws_send_scan_status();

private:
    std::shared_ptr<spdlog::logger> logger_;
    std::mutex mutex_;
    std::queue<std::filesystem::path> files_to_scan_;
    bool traverse_finished_;
    IScanStrategy* scan_strategy_;

    // information of scan.
    ScanStatus scan_status_;
    std::uint32_t total_file_count_;
    std::uint32_t scanned_file_count_;
    std::vector<std::pair<std::string, types::MalwareInfo>> malware_infos_;
    std::filesystem::path curr_scanning_file_;
};
}  // namespace xavcore
