#include "scanner.h"

#include <filesystem>
#include <format>
#include <thread>

#define MAX_FILES_IN_QUEUE 8192

namespace xav {
Scanner::Scanner() : traverse_finished_(false) {}

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
            if (files_to_scan_.empty()) {
                if (this->traverse_finished_) {
                    break;
                } else {
                    continue;
                }
            }
            auto file = files_to_scan_.front();
            std::cout << std::format("Scanning: {}", file.string())
                      << std::endl;
            files_to_scan_.pop();
            lock.unlock();
            auto result = this->exact_hash_engine_.scan(file);
            if (result.has_value()) {
                std::cout << std::format("Malware found: {} is {}",
                                         file.string(),
                                         result.value().variant())
                          << std::endl;
            }
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < nthreads; ++i) {
        threads.push_back(std::thread{scanner});
    }

    for (const auto& entry :
         std::filesystem::recursive_directory_iterator{path}) {
        if (entry.is_regular_file()) {
            std::unique_lock<std::mutex> lock(this->mutex_);
            files_to_scan_.push(entry.path());
        }
    }
    this->traverse_finished_ = true;

    for (auto& thread : threads) {
        thread.join();
    }
}

}  // namespace xav