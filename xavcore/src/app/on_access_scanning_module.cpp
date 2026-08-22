#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <unistd.h>

#include <boost/asio.hpp>
#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <iostream>

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
        const xavcore::MalwareInfoTemp& malware_info) override {
        this->sock_->send(asio::buffer(malware_info.path), 0);
    }

private:
    spdlog::logger* logger_;
    asio::local::seq_packet_protocol::socket* sock_;
};

void startup(spdlog::logger& logger) {
    // I/O context.
    asio::io_context ioc{1};

    // Endpoint.
    std::string socket_path = "/tmp/xavcore_on_access_scanning_module_socket";
    ::unlink(socket_path.c_str());
    asio::local::seq_packet_protocol::endpoint ep(socket_path);

    // Acceptor.
    asio::local::seq_packet_protocol::acceptor acceptor(ioc, ep);

    // Socket.
    asio::local::seq_packet_protocol::socket sock(ioc);

    // Accept connection.
    acceptor.accept(sock);

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

    logger.info("Xavcore On-Access Scanning Module started");

    while (true) {
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
