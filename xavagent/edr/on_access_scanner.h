#pragma once

#include <cstdint>

#include "xavlib/exact_hash.h"

namespace xavagent {
class OnAccessScanner {
public:
    OnAccessScanner();
    ~OnAccessScanner();
    OnAccessScanner(const OnAccessScanner&) = delete;
    OnAccessScanner& operator=(const OnAccessScanner&) = delete;
    OnAccessScanner(OnAccessScanner&&) = delete;
    OnAccessScanner& operator=(OnAccessScanner&&) = delete;

public:
    void start_monitoring();
    void stop_monitoring();

public:
    std::uint64_t scanned_object_count() const {
        return this->scanned_object_count_;
    }
    std::uint64_t blocked_object_count() const {
        return this->blocked_object_count_;
    }

private:
    int fanfd_;
    char* buf_;
    xavlib::ExactHashEngine exact_hash_engine_;
    std::atomic_uint64_t scanned_object_count_;
    std::atomic_uint64_t blocked_object_count_;
};
}  // namespace xavagent
