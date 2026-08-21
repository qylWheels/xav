#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <iostream>
#include <utility>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

void startup() {
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
        startup();
    } catch (std::exception& e) {
        logger->error("Fatal error: {}", e.what());
        cpptrace::generate_trace().print();
        exit(EXIT_FAILURE);
    }
    return 0;
}
