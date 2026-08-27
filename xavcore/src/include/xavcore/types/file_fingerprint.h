#pragma once

#include <sys/stat.h>

#include <boost/container_hash/hash.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

namespace xavcore {
namespace types {
// For cache.
struct FileFingerprint {
    std::uint64_t inode;
    std::uint64_t size;
    std::chrono::time_point<std::chrono::system_clock> mtime;
    std::chrono::time_point<std::chrono::system_clock> ctime;

    FileFingerprint(int fd) {
        struct stat st;
        if (fstat(fd, &st) != 0) {
            throw std::runtime_error("fstat failed");
        }

        inode = st.st_ino;
        size = st.st_size;
        mtime = std::chrono::system_clock::time_point(
            std::chrono::seconds(st.st_mtim.tv_sec) +
            std::chrono::nanoseconds(st.st_mtim.tv_nsec));
        ctime = std::chrono::system_clock::time_point(
            std::chrono::seconds(st.st_ctim.tv_sec) +
            std::chrono::nanoseconds(st.st_ctim.tv_nsec));
    }

    FileFingerprint(const char* path)
        : FileFingerprint(std::filesystem::path(path)) {}

    FileFingerprint(std::string path)
        : FileFingerprint(std::filesystem::path(path)) {}

    FileFingerprint(std::filesystem::path path) {
        struct stat st;
        if (stat(path.c_str(), &st) != 0) {
            throw std::runtime_error("stat failed");
        }

        inode = st.st_ino;
        size = st.st_size;
        mtime = std::chrono::system_clock::time_point(
            std::chrono::seconds(st.st_mtim.tv_sec) +
            std::chrono::nanoseconds(st.st_mtim.tv_nsec));
        ctime = std::chrono::system_clock::time_point(
            std::chrono::seconds(st.st_ctim.tv_sec) +
            std::chrono::nanoseconds(st.st_ctim.tv_nsec));
    }

    bool operator==(const FileFingerprint& other) const {
        return inode == other.inode && size == other.size &&
               mtime == other.mtime && ctime == other.ctime;
    }
};

struct FileFingerprintHash {
    std::size_t operator()(const FileFingerprint& f) const {
        std::size_t seed = 0;
        boost::hash_combine(seed, f.inode);
        boost::hash_combine(seed, f.size);
        boost::hash_combine(
            seed, std::chrono::duration_cast<std::chrono::nanoseconds>(
                      f.mtime.time_since_epoch())
                      .count());
        boost::hash_combine(
            seed, std::chrono::duration_cast<std::chrono::nanoseconds>(
                      f.ctime.time_since_epoch())
                      .count());
        return seed;
    }
};
}  // namespace types
}  // namespace xavcore
