#include "scanner.h"

#include <filesystem>
#include <thread>

#define MAX_FILES_IN_QUEUE 8192

namespace xavagent {
Scanner::Scanner()
    : traverse_finished_(false),
      scan_status_(ScanStatus::Stopped),
      total_file_count_{0},
      scanned_file_count_{0} {}

Scanner::~Scanner() {}

void Scanner::scan(const char* path, int nthreads) {
    this->scan(std::filesystem::path{path}, nthreads);
}

void Scanner::scan(const std::string& path, int nthreads) {
    this->scan(std::filesystem::path{path}, nthreads);
}

void Scanner::scan(const std::filesystem::path& path, int nthreads) {
    auto scanner = [this]() {
        while (true) {
            std::unique_lock<std::mutex> lock(this->mutex_);
            if (this->files_to_scan_.empty()) {
                if (this->traverse_finished_) {
                    break;
                } else {
                    continue;
                }
            }
            auto file = this->files_to_scan_.front();
            this->files_to_scan_.pop();
            this->curr_scanning_file_ = file;
            auto result = this->exact_hash_engine_.scan(file);
            this->scanned_file_count_++;
            if (result.has_value()) {
                this->malware_infos_.push_back({file, result.value()});
            }
            lock.unlock();
        }
    };

    this->scan_status_ = ScanStatus::Scanning;
    std::vector<std::thread> threads;
    for (int i = 0; i < nthreads; ++i) {
        threads.push_back(std::thread{scanner});
    }

    // Traverse directory to find files to scan.
    try {
        for (const auto& entry :
             std::filesystem::recursive_directory_iterator{path}) {
            if (entry.is_regular_file()) {
                std::unique_lock<std::mutex> lock(this->mutex_);
                this->total_file_count_++;
                this->files_to_scan_.push(entry.path());
            }
        }
    } catch (std::filesystem::filesystem_error& e) {
        // TODO: We just ignore the error for now, but we should log it and
        // transfer information related to the error to the client.
    }
    this->traverse_finished_ = true;

    for (auto& thread : threads) {
        thread.join();
    }
    this->scan_status_ = ScanStatus::Stopped;

    // Reset states
    std::lock_guard<std::mutex> lock(mutex_);
    this->traverse_finished_ = false;
    this->files_to_scan_ = {};
}

}  // namespace xavagent