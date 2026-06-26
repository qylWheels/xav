#pragma once

#include <filesystem>
#include <string>

namespace xav {
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
};
}  // namespace xav
