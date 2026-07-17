#pragma once

#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <leveldb/db.h>

#include <filesystem>
#include <optional>
#include <string>

#include "protobufs/malware_info.pb.h"

namespace xavagent {
class ExactHashEngine {
public:
    ExactHashEngine();
    ~ExactHashEngine();
    ExactHashEngine(const ExactHashEngine&) = delete;
    ExactHashEngine& operator=(const ExactHashEngine&) = delete;
    ExactHashEngine(ExactHashEngine&&) = delete;
    ExactHashEngine& operator=(ExactHashEngine&&) = delete;

public:
    std::optional<malware_info::MalwareInfo> scan(const std::string& path);
    std::optional<malware_info::MalwareInfo> scan(
        const std::filesystem::path& path);

private:
    std::string calc_sha256_of_file(const char* path) const;

private:
    leveldb::DB* db_;
};
}  // namespace xavagent
