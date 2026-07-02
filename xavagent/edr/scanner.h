#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include "xavlib/exact_hash.h"
#include "xavlib/malware_info.pb.h"

namespace xavagent {
struct MalwareInfo {
    std::filesystem::path file_path;
    malware_info::MalwareInfo malware_info;
};

class Scanner {
public:
    Scanner();
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

    std::vector<MalwareInfo> malware_infos() {
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

private:
    std::mutex mutex_;
    std::queue<std::filesystem::path> files_to_scan_;
    xavlib::ExactHashEngine exact_hash_engine_;
    bool traverse_finished_;
    std::uint32_t total_file_count_;
    std::uint32_t scanned_file_count_;
    std::vector<MalwareInfo> malware_infos_;
    std::filesystem::path curr_scanning_file_;
};
}  // namespace xavagent
