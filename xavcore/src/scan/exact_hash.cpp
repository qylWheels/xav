#include "xavcore/scan/exact_hash.h"

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <zconf.h>
#include <zlib.h>

#include <cstddef>
#include <format>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <outcome/success_failure.hpp>
#include <stdexcept>

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

outcome::result<std::optional<std::pair<std::string, types::MalwareInfo>>>
ExactHashEngine::scan(const std::string& path) {
    return this->scan(std::filesystem::path{path});
}

outcome::result<std::optional<std::pair<std::string, types::MalwareInfo>>>
ExactHashEngine::scan(const std::filesystem::path& path) {
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
        // Uncompress.
        std::size_t decompressed_size_hint = 4096;
        std::vector<std::uint8_t> buf(decompressed_size_hint);
        int ret = ::uncompress(
            buf.data(), &decompressed_size_hint,
            reinterpret_cast<const Bytef*>(raw_malware_info.data()),
            raw_malware_info.size());
        if (ret != Z_OK) {
            this->logger_->warn(std::format("failed to uncompress: {}", ret));
            return outcome::failure(
                std::make_error_code(std::errc::invalid_argument));
        }

        // Deserialize.
        types::MalwareInfo malware_info;
        nlohmann::json j = nlohmann::json::parse(buf);
        malware_info.vendor = j["vendor"].get<std::string>();
        malware_info.engine = j["engine"].get<std::string>();
        malware_info.threat_name = j["threat_name"].get<std::string>();
        malware_info.likelihood = j["likelihood"].get<double>();
        malware_info.severity = j["severity"].get<double>();

        return outcome::success(std::make_pair(path.string(), malware_info));
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
