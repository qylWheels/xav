#include <httplib.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <exception>
#include <iostream>
#include <memory>
#include <thread>

#include "xavcore/protection/hips/monitor/hips_monitor.h"
#include "xavcore/protection/on_access_scanning/on_access_scanner.h"
#include "xavcore/protection/proactive_protection/behavior_monitor.h"
// #include
// "xavcore/protection/proactive_protection/event_listener/anomalous_syscall_detection_listener/anomalous_syscall_detection_listener.h"
#include "xavcore/protection/proactive_protection/event_listener/placeholder_event_listener/placeholder_event_listener.h"
#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_based_detection_listener.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event_provider.h"
#include "xavcore/scan/exact_hash.h"
#include "xavcore/scan/normal_scan_strategy.h"
#include "xavcore/scan/scanner.h"
#include "xavcore/scan/yara_static_heuristic_engine.h"

void sigsegv_handler(int signum) {
    std::cerr << "SIGSEGV signal received" << std::endl;
    cpptrace::generate_trace().print();
    std::exit(signum);
}

void startup() {
    auto logger = spdlog::stdout_color_mt(__FUNCTION__);
    logger->set_level(spdlog::level::info);

    // Setup scan engines and scan strategy.
    xavcore::ExactHashEngine exact_hash_engine;
    xavcore::YaraStaticHeuristicEngine yara_static_heuristic_engine;
    std::unique_ptr<xavcore::IScanStrategy> normal_scan_strategy =
        std::make_unique<xavcore::NormalScanStrategy>(
            exact_hash_engine, yara_static_heuristic_engine);

    // Event providers.
    std::shared_ptr<xavcore::IEventProvider> syscall_event_provider =
        std::make_shared<xavcore::SyscallEventProvider>();

    // Event listeners.
    std::shared_ptr<xavcore::IEventListener> placeholder_event_listener =
        std::make_shared<xavcore::PlaceholderEventListener>();
    // std::shared_ptr<xavcore::IEventListener>
    //     anomalous_syscall_detection_listener =
    //         std::make_shared<xavcore::AnomalousSyscallDetectionListener>(
    //             *logger);
    std::shared_ptr<xavcore::IEventListener> rule_based_detection_listener =
        std::make_shared<xavcore::RuleBasedDetectionListener>(*logger);
    auto ret =
        syscall_event_provider->listener_register(*placeholder_event_listener);
    if (!ret) {
        logger->error("Failed to register syscall event listener: {}",
                      ret.error().message());
        return;
    }
    // ret = syscall_event_provider->listener_register(
    //     *anomalous_syscall_detection_listener);
    // if (!ret) {
    //     logger->error(
    //         "Failed to register anomalous syscall detection listener: {}",
    //         ret.error().message());
    //     return;
    // }
    ret = syscall_event_provider->listener_register(
        *rule_based_detection_listener);
    if (!ret) {
        logger->error("Failed to register rule based detection listener: {}",
                      ret.error().message());
        return;
    }

    // HIPS monitor.
    auto hips_monitor = std::make_shared<xavcore::HipsMonitor>(*logger);

    // Start protection.
    ret = syscall_event_provider->start();
    if (!ret) {
        logger->error("Failed to start syscall monitor: {}",
                      ret.error().message());
        return;
    }
    xavcore::OnAccessScanner on_access_scanner(*normal_scan_strategy);
    std::jthread on_access_scanner_thread(
        [&on_access_scanner]() { on_access_scanner.start_monitoring(); });
    ret = hips_monitor->start();
    if (!ret) {
        logger->error("Failed to start HIPS monitor: {}",
                      ret.error().message());
        return;
    }

    // Configure API server.
    httplib::Server http_server;
    xavcore::Scanner scanner(*normal_scan_strategy);
    http_server.Get("/scan/quick/start", [&logger, &scanner](
                                             const httplib::Request& req,
                                             httplib::Response& res) {
        if (scanner.scan_status() != xavcore::ScanStatus::Stopped) {
            logger->warn("Quick scan is already running!");
            res.status = 403;
            return;
        }

        logger->info("Quick scan started");
        std::jthread t([&scanner, logger]() {
            // std::vector<std::string> critical_paths{
            //     "/home", "/tmp",     "/var/tmp", "/bin",
            //     "/sbin", "/usr/bin", "/usr/sbin"};
            // FIXME: Only for test.
            std::vector<const char*> critical_paths{"/home/qyl/projects/xav/"};
            for (const auto& path : critical_paths) {
                scanner.scan(path, 4);
            }
            logger->info("Quick scan completed");
        });
        t.detach();

        res.status = 200;
        return;
    });

    logger->info(std::format("XAV agent started at {}:{}", "0.0.0.0", "8000"));
    http_server.listen("0.0.0.0", 8000);

    return;
}

int main(int argc, const char* argv[]) {
    std::signal(SIGSEGV, sigsegv_handler);
    auto logger = spdlog::stdout_color_mt(__FUNCTION__);
    logger->set_level(spdlog::level::info);
    try {
        startup();
    } catch (std::exception& e) {
        logger->error("Fatal error: {}", e.what());
        cpptrace::generate_trace().print();
        exit(EXIT_FAILURE);
    }
}
