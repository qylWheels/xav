#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>
#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <iostream>

#include "xavcore/protection/proactive_protection/event_listener/rule_based_detection_listener/rule_based_detection_listener.h"
#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/syscall_event_provider.h"

namespace asio = boost::asio;

void startup(spdlog::logger& logger) {
    // I/O context.
    asio::io_context ioc;

    // Endpoint.
    std::string socket_path =
        std::string("\0", 1) + "xavcore_proactive_protection_module_socket";
    asio::local::seq_packet_protocol::endpoint ep(socket_path);

    // Acceptor.
    asio::local::seq_packet_protocol::acceptor acceptor(ioc, ep);

    // Socket.
    asio::local::seq_packet_protocol::socket sock(ioc);

    // Event providers.
    xavcore::SyscallEventProvider syscall_event_provider;

    // Event listeners.
    xavcore::RuleBasedDetectionListener rule_based_detection_listener(logger);
    auto ret =
        syscall_event_provider.listener_register(rule_based_detection_listener);
    if (!ret) {
        logger.error("Failed to register rule based detection listener: {}",
                     ret.error().message());
        return;
    }

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