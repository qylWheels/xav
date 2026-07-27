#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <exception>
#include <iostream>
#include <memory>
#include <thread>

#include "xavagent/global_context/global_context.h"
#include "xavagent/protection/behavior_monitor.h"
#include "xavagent/protection/event_listener/levenshtein.h"
#include "xavagent/protection/event_provider/syscall_monitor/syscall_monitor.h"
#include "xavagent/scan/yara_static_heuristic_engine.h"

namespace http = beast::http;

void sigsegv_handler(int signum) {
    std::cerr << "SIGSEGV signal received" << std::endl;
    cpptrace::generate_trace().print();
    std::exit(signum);
}

void init() {
    auto logger = spdlog::stdout_color_mt("init");
    logger->set_level(spdlog::level::info);

    // Websocket configs.
    auto& ws = xavagent::GlobalContext::get_global_context().ws();
    auto& ioc = static_cast<net::io_context&>(ws.get_executor().context());
    std::string host = "0.0.0.0";
    std::string port = "8001";
    tcp::resolver resolver{ioc};
    auto const results = resolver.resolve(host, port);
    auto ep = net::connect(ws.next_layer(), results);
    host += ':' + std::to_string(ep.port());
    ws.set_option(
        websocket::stream_base::decorator([](websocket::request_type& req) {
            req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " websocket-client-coro");
        }));
    ws.binary(true);
    ws.handshake(host, "/ws");

    // Start a thread to read from websocket to handle ping frame.
    std::jthread ws_read_thread([&ws]() {
        while (true) {
            beast::flat_buffer buffer;
            ws.read(buffer);
        }
    });
    ws_read_thread.detach();

    // Add Yara static heuristic engine to the manager.
    xavagent::GlobalContext::get_global_context()
        .static_heur_engine_manager()
        .add_engine(std::make_shared<xavagent::YaraStaticHeuristicEngine>());

    // Event providers.
    std::shared_ptr<xavagent::IEventProvider> syscall_monitor =
        std::make_shared<xavagent::SyscallMonitor>();

    // Event listeners.
    std::shared_ptr<xavagent::IEventListener> levenshtein_listener =
        std::make_shared<xavagent::Levenshtein>();
    auto ret = syscall_monitor->listener_register(levenshtein_listener);
    if (!ret) {
        logger->error("Failed to register listener: {}", ret.error().message());
        return;
    }

    // Start protection.
    std::jthread on_access_scanner_thread([]() {
        xavagent::GlobalContext::get_global_context()
            .on_access_scanner()
            .start_monitoring();
    });
    on_access_scanner_thread.detach();

    // Configure API server.
    auto& server = xavagent::GlobalContext::get_global_context().httpserver();
    server.Get("/scan/quick/start", [logger](const httplib::Request& req,
                                             httplib::Response& res) {
        auto& scanner = xavagent::GlobalContext::get_global_context().scanner();
        if (scanner.scan_status() != xavagent::ScanStatus::Stopped) {
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
}

int main(int argc, const char* argv[]) {
    std::signal(SIGSEGV, sigsegv_handler);
    auto logger = spdlog::stdout_color_mt("main");
    logger->set_level(spdlog::level::info);
    try {
        init();
        logger->info(
            std::format("XAV agent started at {}:{}", "0.0.0.0", "8000"));
        return xavagent::GlobalContext::get_global_context()
            .httpserver()
            .listen("0.0.0.0", 8000);
    } catch (std::exception& e) {
        logger->error("Fatal error: {}", e.what());
        cpptrace::generate_trace().print();
        exit(EXIT_FAILURE);
    }
}
