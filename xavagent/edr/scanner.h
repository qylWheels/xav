#pragma once

#include <filesystem>
#include <mutex>
#include <queue>
#include <string>

#include "xavlib/exact_hash.h"

namespace xavagent {
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

private:
    std::mutex mutex_;
    std::queue<std::filesystem::path> files_to_scan_;
    xavlib::ExactHashEngine exact_hash_engine_;
    bool traverse_finished_;
};
}  // namespace xavagent
