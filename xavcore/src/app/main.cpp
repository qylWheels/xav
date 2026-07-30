#include <httplib.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <exception>
#include <iostream>
#include <memory>
#include <thread>

#include "xavcore/protection/behavior_monitor.h"
#include "xavcore/protection/event_listener/levenshtein.h"
#include "xavcore/protection/event_provider/syscall_monitor/syscall_monitor.h"
#include "xavcore/protection/on_access_scanner.h"
#include "xavcore/scan/exact_hash.h"
#include "xavcore/scan/normal_scan_strategy.h"
#include "xavcore/scan/scanner.h"
#include "xavcore/scan/yara_static_heuristic_engine.h"

namespace beast = boost::beast;
namespace websocket = beast::websocket;
using tcp = boost::asio::ip::tcp;
namespace net = boost::asio;
namespace http = beast::http;

void sigsegv_handler(int signum) {
    std::cerr << "SIGSEGV signal received" << std::endl;
    cpptrace::generate_trace().print();
    std::exit(signum);
}

void startup() {
    auto logger = spdlog::stdout_color_mt(__FUNCTION__);
    logger->set_level(spdlog::level::info);

    // Websocket configs.
    auto ioc = net::io_context{};
    websocket::stream<tcp::socket> ws{net::make_strand(ioc)};
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

    // Setup scan engines and scan strategy.
    xavcore::ExactHashEngine exact_hash_engine;
    xavcore::YaraStaticHeuristicEngine yara_static_heuristic_engine;
    std::unique_ptr<xavcore::IScanStrategy> normal_scan_strategy =
        std::make_unique<xavcore::NormalScanStrategy>(
            exact_hash_engine, yara_static_heuristic_engine);

    // Event providers.
    std::shared_ptr<xavcore::IEventProvider> syscall_monitor =
        std::make_shared<xavcore::SyscallMonitor>();

    // Event listeners.
    std::shared_ptr<xavcore::IEventListener> levenshtein_listener =
        std::make_shared<xavcore::Levenshtein>();
    auto ret = syscall_monitor->listener_register(*levenshtein_listener);
    if (!ret) {
        logger->error("Failed to register listener: {}", ret.error().message());
        return;
    }

    // Start protection.
    ret = syscall_monitor->start();
    if (!ret) {
        logger->error("Failed to start syscall monitor: {}",
                      ret.error().message());
        return;
    }
    xavcore::OnAccessScanner on_access_scanner(*normal_scan_strategy);
    std::jthread on_access_scanner_thread(
        [&on_access_scanner]() { on_access_scanner.start_monitoring(); });

    // Configure API server.
    httplib::Server http_server;
    xavcore::Scanner scanner(*normal_scan_strategy, ws);
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
