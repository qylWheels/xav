#include "xavcore/scan/exact_hash.h"

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <format>
#include <outcome/success_failure.hpp>
#include <stdexcept>

#include "malware_info.pb.h"

namespace xavcore {
ExactHashEngineDatabase::~ExactHashEngineDatabase() { delete this->db; }

leveldb::DB* ExactHashEngineDatabase::get_db() {
    static ExactHashEngineDatabase db;
    return db.db;
}

ExactHashEngineDatabase::ExactHashEngineDatabase() {
    // Initialize db.
    leveldb::Status status =
        leveldb::DB::Open(leveldb::Options{}, XAV_EXACT_HASH_DB, &this->db);
    if (!status.ok()) {
        throw std::runtime_error("leveldb::DB::Open failed");
    }
}

ExactHashEngine::ExactHashEngine() {
    this->logger_ = spdlog::stdout_color_mt("exact_hash_engine");
    this->logger_->set_level(spdlog::level::info);
}

ExactHashEngine::~ExactHashEngine() {}

outcome::result<std::optional<malware_info::MalwareInfo>> ExactHashEngine::scan(
    const std::string& path) {
    return this->scan(std::filesystem::path{path});
}

outcome::result<std::optional<malware_info::MalwareInfo>> ExactHashEngine::scan(
    const std::filesystem::path& path) {
    std::string sha256;
    try {
        sha256 = this->calc_sha256_of_file(path.c_str());
    } catch (const CryptoPP::Exception&) {
        this->logger_->error(
            std::format("Error: failed to scan {}", path.string()));
        return outcome::failure(std::make_error_code(std::errc::io_error));
    }
    std::string raw_malware_info;
    leveldb::Status status = ExactHashEngineDatabase::get_db()->Get(
        leveldb::ReadOptions{}, sha256, &raw_malware_info);
    if (!status.ok()) {
        return outcome::failure(std::make_error_code(std::errc::io_error));
    } else {
        malware_info::MalwareInfo malware_info;
        auto result = malware_info.ParseFromString(raw_malware_info);
        if (!result) {
            return outcome::failure(
                std::make_error_code(std::errc::invalid_argument));
        } else {
            return outcome::success(malware_info);
        }
    }
}

std::string ExactHashEngine::calc_sha256_of_file(const char* path) const {
    std::string digest;
    CryptoPP::SHA256 sha256;
    CryptoPP::FileSource file_source{
        path, true,
        new CryptoPP::HashFilter(
            sha256,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false))};
    return digest;
}
}  // namespace xavcore
