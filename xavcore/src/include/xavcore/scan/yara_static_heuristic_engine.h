#pragma once

#include <spdlog/spdlog.h>
#include <yara.h>

#include <format>
#include <iostream>
#include <memory>

#include "xavcore/scan/static_heuristic.h"
#include "xavcore/types/malware_info.h"

namespace xavcore {
class YaraStaticHeuristicEngine : public IStaticHeuristicEngine {
public:
    YaraStaticHeuristicEngine();
    ~YaraStaticHeuristicEngine();

public:
    virtual outcome::result<
        std::optional<std::pair<std::string, types::MalwareInfo>>>
    scan(const std::filesystem::path& path) override;

private:
    static void yara_err_callback(int error_level, const char* file_name,
                                  int line_number, const YR_RULE* rule,
                                  const char* message, void* user_data) {
        const char* level =
            (error_level == YARA_ERROR_LEVEL_ERROR) ? "Error" : "Warning";
        std::cerr << std::format("{}: {} (file: {}, line: {})\n", level,
                                 message, file_name ? file_name : "<unknown>",
                                 line_number)
                  << std::endl;
    }

    static int yara_scan_callback(YR_SCAN_CONTEXT* context, int message,
                                  void* message_data, void* user_data);

private:
    std::shared_ptr<spdlog::logger> logger_;
    YR_COMPILER* yara_compiler_;
    YR_RULES* yara_rules_;
};
}  // namespace xavcore
