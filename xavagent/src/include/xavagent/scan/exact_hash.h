#pragma once

#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <leveldb/db.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>

#include "malware_info.pb.h"

// FIXME: Only for tests.
#define XAV_EXACT_HASH_DB \
    "/home/qyl/projects/xav/xavdb/db/malware-bazaar-sha256.db"

namespace xavagent {
class ExactHashEngineDatabase {
public:
    ~ExactHashEngineDatabase() { delete this->db; }

public:
    static leveldb::DB* get_db() {
        static ExactHashEngineDatabase db;
        return db.db;
    }

private:
    ExactHashEngineDatabase() {
        // Initialize db.
        leveldb::Status status =
            leveldb::DB::Open(leveldb::Options{}, XAV_EXACT_HASH_DB, &this->db);
        if (!status.ok()) {
            throw std::runtime_error("leveldb::DB::Open failed");
        }
    }

private:
    leveldb::DB* db;
};

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
    std::shared_ptr<spdlog::logger> logger_;
};
}  // namespace xavagent
