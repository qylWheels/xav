#include "xavcore/utils/cache/cache.h"

namespace xavcore {
namespace utils {
namespace cache {
auto Cache::add(types::FileFingerprint fp, types::MalwareInfo mi)
    -> decltype(cache_.insert({fp, mi})) {
    return this->cache_.insert({fp, mi});
}

void Cache::remove(const types::FileFingerprint& fp) { this->cache_.erase(fp); }

std::optional<std::optional<types::MalwareInfo>> Cache::get(
    const types::FileFingerprint& fp) {
    auto it = this->cache_.find(fp);
    if (it != this->cache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void Cache::clear() { this->cache_.clear(); }
}  // namespace cache
}  // namespace utils
}  // namespace xavcore
