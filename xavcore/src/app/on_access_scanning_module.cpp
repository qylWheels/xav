#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <unistd.h>

#include <boost/asio.hpp>
#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

#include "xavcore/protection/on_access_scanning/on_access_scanner.h"
#include "xavcore/scan/exact_hash.h"
#include "xavcore/scan/normal_scan_strategy.h"
#include "xavcore/scan/yara_static_heuristic_engine.h"

namespace asio = boost::asio;

class EventListener : public xavcore::IOnAccessScannerEventListener {
public:
    EventListener(spdlog::logger& logger,
                  asio::local::seq_packet_protocol::socket& sock)
        : logger_(&logger), sock_(&sock) {}

public:
    virtual void on_event(
        const std::string_view path,
        const xavcore::types::MalwareInfo& malware_info) override {
        try {
            nlohmann::json j = {
                {"path", path},
                {"threat_name", malware_info.threat_name},
            };
            this->sock_->send(asio::buffer(j.dump()), 0);
        } catch (std::exception& e) {
            logger_->warn("Failed to send malware info: {}", e.what());
        }
    }

private:
    spdlog::logger* logger_;
    asio::local::seq_packet_protocol::socket* sock_;
};

void startup(spdlog::logger& logger) {
    // I/O context.
    asio::io_context ioc;

    // Endpoint.
    std::string socket_path =
        std::string("\0", 1) + "xavcore_on_access_scanning_module_socket";
    asio::local::seq_packet_protocol::endpoint ep(socket_path);

    // Acceptor.
    asio::local::seq_packet_protocol::acceptor acceptor(ioc, ep);

    // Socket.
    asio::local::seq_packet_protocol::socket sock(ioc);

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
    EventListener listener(logger, sock);
    on_access_scanner.add_event_listener(listener);

    // Accept connection asynchronously.
    acceptor.async_accept(sock, [&](boost::system::error_code ec) {
        if (ec) {
            logger.warn("Accept error: {}", ec.message());
        } else {
            logger.info("Client connected");
        }
    });

    logger.info("Xavcore On-Access Scanning Module started");

    ioc.run();

    while (true);
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
