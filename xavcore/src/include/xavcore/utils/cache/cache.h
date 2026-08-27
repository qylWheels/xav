#pragma once

#include <optional>
#include <unordered_map>

#include "xavcore/types/file_fingerprint.h"
#include "xavcore/types/malware_info.h"

namespace xavcore {
namespace utils {
namespace cache {
class Cache {
public:
    Cache() = default;
    ~Cache() = default;
    Cache(const Cache&) = delete;
    Cache& operator=(const Cache&) = delete;
    Cache(Cache&&) = delete;
    Cache& operator=(Cache&&) = delete;

public:
    // Return old malware info if the map already exists.
    std::optional<types::MalwareInfo> add(types::FileFingerprint fp,
                                          types::MalwareInfo mi);
    void remove(const types::FileFingerprint& fp);
    std::optional<types::MalwareInfo> get(const types::FileFingerprint& fp);
    void clear();

private:
    std::unordered_map<types::FileFingerprint, types::MalwareInfo,
                       types::FileFingerprintHash>
        cache_;
};
}  // namespace cache
}  // namespace utils
}  // namespace xavcore
