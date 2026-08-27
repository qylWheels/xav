#pragma once

#include <sys/stat.h>

#include <boost/container_hash/hash.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

namespace xavcore {
namespace types {
struct FileFingerprintHash;

// For cache.
struct FileFingerprint {
    friend FileFingerprintHash;

public:
    FileFingerprint(int fd);
    FileFingerprint(const char* path);
    FileFingerprint(std::string path);
    FileFingerprint(std::filesystem::path path);
    bool operator==(const FileFingerprint& other) const;

private:
    std::uint64_t inode;
    std::uint64_t size;
    std::chrono::time_point<std::chrono::system_clock> mtime;
    std::chrono::time_point<std::chrono::system_clock> ctime;
};

struct FileFingerprintHash {
    std::size_t operator()(const FileFingerprint& f) const;
};
}  // namespace types
}  // namespace xavcore
