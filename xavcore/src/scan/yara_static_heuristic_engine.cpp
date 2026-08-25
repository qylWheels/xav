#include "xavcore/scan/yara_static_heuristic_engine.h"

#include <fcntl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <unistd.h>
#include <yara.h>

#include <format>
#include <system_error>
#include <utility>

namespace xavcore {
#define YARA_RULES_FILE \
    "/home/qyl/projects/xav/xavdb/db/yara-rules-extended.yar"
#define YARA_FORGE_NAMESPACE "yara_forge"

YaraStaticHeuristicEngine::YaraStaticHeuristicEngine()
    : yara_compiler_(nullptr), yara_rules_(nullptr) {
    this->logger_ =
        spdlog::stderr_color_mt("yara static heuristic engine logger");
    this->logger_->set_level(spdlog::level::info);

    int ret;

    yr_initialize();

    // Create a Yara compiler.
    ret = yr_compiler_create(&this->yara_compiler_);
    if (ret != ERROR_SUCCESS) {
        throw std::runtime_error(
            std::format("yr_compiler_create failed: {}", ret));
    }

    // Set the error callback.
    yr_compiler_set_callback(this->yara_compiler_,
                             YaraStaticHeuristicEngine::yara_err_callback,
                             nullptr);

    // Add rules to the compiler.
    int rule_fd = open(YARA_RULES_FILE, O_RDONLY);
    if (rule_fd < 0) {
        throw std::runtime_error(
            std::format("open yara rule file failed: {}", ret));
    }
    ret = yr_compiler_add_fd(this->yara_compiler_, rule_fd,
                             YARA_FORGE_NAMESPACE, nullptr);
    if (ret != ERROR_SUCCESS) {
        throw std::runtime_error(
            std::format("yr_compiler_add_fd failed: {}", ret));
    }
    close(rule_fd);

    // Get the compiled rules.
    ret = yr_compiler_get_rules(this->yara_compiler_, &this->yara_rules_);
    if (ret != ERROR_SUCCESS) {
        throw std::runtime_error(
            std::format("yr_compiler_get_rules failed: {}", ret));
    }
}

YaraStaticHeuristicEngine::~YaraStaticHeuristicEngine() {
    yr_rules_destroy(this->yara_rules_);
    yr_compiler_destroy(this->yara_compiler_);
    yr_finalize();
}

outcome::result<std::optional<std::pair<std::string, types::MalwareInfo>>>
YaraStaticHeuristicEngine::scan(const std::filesystem::path& path) {
    std::optional<std::pair<std::string, types::MalwareInfo>> result =
        std::nullopt;
    auto user_data = std::make_pair(this, &result);
    int ret = yr_rules_scan_file(
        this->yara_rules_, path.c_str(),
        SCAN_FLAGS_REPORT_RULES_MATCHING | SCAN_FLAGS_FAST_MODE,
        YaraStaticHeuristicEngine::yara_scan_callback, &user_data, 0);
    if (ret != ERROR_SUCCESS) {
        return std::make_error_code(std::errc::io_error);
    }
    result->first = path.string();
    return result;
}

int YaraStaticHeuristicEngine::yara_scan_callback(YR_SCAN_CONTEXT* context,
                                                  int message,
                                                  void* message_data,
                                                  void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        // Get the user data.
        auto user_data_pair = static_cast<std::pair<
            YaraStaticHeuristicEngine*,
            std::optional<std::pair<std::string, types::MalwareInfo>>*>*>(
            user_data);
        auto self = user_data_pair->first;
        auto result = user_data_pair->second;

        // Get the score from rule.
        YR_RULE* rule = (YR_RULE*)message_data;
        YR_META* meta;
        double score = 0.0;
        yr_rule_metas_foreach(rule, meta) {
            if (strcmp(meta->identifier, "score") == 0) {
                score = meta->integer;
                break;
            }
        }

        // Set the result.
        types::MalwareInfo malware_info;
        malware_info.vendor = "YaraForge";
        malware_info.engine = "Static Heuristic Detection Engine";
        malware_info.threat_name = rule->identifier;
        malware_info.likelihood = score;
        malware_info.severity = score;
        *result = std::make_pair("", malware_info);

        return CALLBACK_CONTINUE;
    }
    return CALLBACK_CONTINUE;
}
}  // namespace xavcore
