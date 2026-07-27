#pragma once

#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <leveldb/db.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <optional>
#include <string>

#include "malware_info.pb.h"
#include "xavagent/scan/scan_interfaces.h"

// FIXME: Only for tests.
#define XAV_EXACT_HASH_DB \
    "/home/qyl/projects/xav/xavdb/db/malware-bazaar-sha256.db"

namespace xavagent {
class ExactHashEngineDatabase {
public:
    ~ExactHashEngineDatabase();

public:
    static leveldb::DB* get_db();

private:
    ExactHashEngineDatabase();

private:
    leveldb::DB* db;
};

class ExactHashEngine : public IScanEngine {
public:
    ExactHashEngine();
    ~ExactHashEngine();
    ExactHashEngine(const ExactHashEngine&) = delete;
    ExactHashEngine& operator=(const ExactHashEngine&) = delete;
    ExactHashEngine(ExactHashEngine&&) = delete;
    ExactHashEngine& operator=(ExactHashEngine&&) = delete;

public:
    outcome::result<std::optional<malware_info::MalwareInfo>> scan(
        const std::string& path);
    outcome::result<std::optional<malware_info::MalwareInfo>> scan(
        const std::filesystem::path& path) override;

private:
    std::string calc_sha256_of_file(const char* path) const;

private:
    std::shared_ptr<spdlog::logger> logger_;
};
}  // namespace xavagent
