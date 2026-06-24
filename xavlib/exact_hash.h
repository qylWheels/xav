#pragma once

#include <filesystem>
#include <optional>
#include <string>

#include "malware_info.h"

namespace xav {
class ExactHashEngine {
public:
    ExactHashEngine() = default;
    ~ExactHashEngine() = default;

    std::optional<MalwareInfo> scan(const std::string& path);
    std::optional<MalwareInfo> scan(const std::filesystem::path& path);
};
}  // namespace xav
