#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <iostream>
#include <utility>

#include "xavcore/protection/on_access_scanning/on_access_scanner.h"
#include "xavcore/scan/exact_hash.h"
#include "xavcore/scan/normal_scan_strategy.h"
#include "xavcore/scan/yara_static_heuristic_engine.h"

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

class EventListener : public xavcore::IOnAccessScannerEventListener {
public:
    EventListener(spdlog::logger& logger) : logger_(&logger) {}

public:
    virtual void on_event(const xavcore::MalwareInfo& malware_info) override {
        logger_->info("Path: {}, Threat: {}", malware_info.path,
                      malware_info.family.value_or("Unknown"));
    }

private:
    spdlog::logger* logger_;
};

void startup(spdlog::logger& logger) {
    // I/O context.
    net::io_context ioc{1};

    // TCP connection.
    tcp::acceptor acceptor{
        ioc, tcp::endpoint(net::ip::make_address("0.0.0.0"), 8000)};
    tcp::socket socket = acceptor.accept();

    // WebSocket connection.
    websocket::stream<tcp::socket> ws(std::move(socket));
    ws.set_option(
        websocket::stream_base::decorator([](websocket::response_type& res) {
            res.set(http::field::server, "Xavcore Proactive Protection Module");
        }));
    ws.accept();

    // Start on-access scanning.
    xavcore::ExactHashEngine exact_hash_engine;
    xavcore::YaraStaticHeuristicEngine yara_static_heuristic_engine;
    std::unique_ptr<xavcore::IScanStrategy> normal_scan_strategy =
        std::make_unique<xavcore::NormalScanStrategy>(
            exact_hash_engine, yara_static_heuristic_engine);
    xavcore::OnAccessScanner on_access_scanner(logger, *normal_scan_strategy);
    if (on_access_scanner.start_monitoring().has_error()) {
        logger.error("Failed to start on-access scanning: {}",
                     on_access_scanner.start_monitoring().error().message());
        return;
    }
    EventListener listener(logger);
    on_access_scanner.add_event_listener(listener);

    logger.info("Xavcore On-Access Scanning Module started");

    // Handle messages from the client
    while (true) {
        ws.write(net::buffer("Hello, World!"));
    }
}

void sigsegv_handler(int signum) {
    std::cerr << "SIGSEGV signal received" << std::endl;
    cpptrace::generate_trace().print();
    std::exit(signum);
}

int main(int argc, char* argv[]) {
    std::signal(SIGSEGV, sigsegv_handler);
    auto logger = spdlog::stdout_color_mt("Xavcore On-Access Scanning Module");
    logger->set_level(spdlog::level::info);
    try {
        startup(*logger);
    } catch (std::exception& e) {
        logger->error("Fatal error: {}", e.what());
        cpptrace::generate_trace().print();
        exit(EXIT_FAILURE);
    }
    return 0;
}
