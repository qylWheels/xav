#include "exact_hash.h"

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <format>

#include "malware_info.pb.h"

// FIXME: Only for tests.
#define XAV_EXACT_HASH_DB \
    "/home/comma/projs/xav-db/malware_database/malware-bazaar-sha256.db"

namespace xavlib {
ExactHashEngine::ExactHashEngine() {
    leveldb::Status status =
        leveldb::DB::Open(leveldb::Options{}, XAV_EXACT_HASH_DB, &this->db_);
    if (!status.ok()) {
        perror("leveldb::DB::Open");
        exit(1);
    }
}

ExactHashEngine::~ExactHashEngine() {
    delete this->db_;
    this->db_ = nullptr;
}

std::optional<malware_info::MalwareInfo> ExactHashEngine::scan(
    const std::string& path) {
    return this->scan(std::filesystem::path{path});
}

std::optional<malware_info::MalwareInfo> ExactHashEngine::scan(
    const std::filesystem::path& path) {
    std::string sha256;
    try {
        sha256 = this->calc_sha256_of_file(path.c_str());
    } catch (const CryptoPP::Exception&) {
        std::cerr << std::format("Error: failed to scan {}.\n", path.string());
        return std::nullopt;
    }
    std::string raw_malware_info;
    leveldb::Status status =
        this->db_->Get(leveldb::ReadOptions{}, sha256, &raw_malware_info);
    if (!status.ok()) {
        return std::nullopt;
    } else {
        malware_info::MalwareInfo malware_info;
        malware_info.ParseFromString(raw_malware_info);
        return malware_info;
    }
}

std::string ExactHashEngine::calc_sha256_of_file(const char* path) const {
    std::string digest;
    CryptoPP::SHA256 sha256;
    CryptoPP::FileSource{
        path, true,
        new CryptoPP::HashFilter(
            sha256,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false))};
    return digest;
}
}  // namespace xavlib