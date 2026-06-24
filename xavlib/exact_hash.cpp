#include "exact_hash.h"

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#define XAV_EXACT_HASH_DB "xav_exact_hash.db"

namespace xav {
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

std::optional<MalwareInfo> ExactHashEngine::scan(const std::string& path) {
    return this->scan(std::filesystem::path{path});
}

std::optional<MalwareInfo> ExactHashEngine::scan(
    const std::filesystem::path& path) {
    std::string sha256 = this->calc_sha256_of_file(path.c_str());
    std::string raw_malware_info;
    leveldb::Status status =
        this->db_->Get(leveldb::ReadOptions{}, sha256, &raw_malware_info);
    if (!status.ok()) {
        return std::nullopt;
    } else {
        MalwareInfo malware_info =
            *reinterpret_cast<MalwareInfo*>(raw_malware_info.data());
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
}  // namespace xav
