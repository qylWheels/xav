#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <exception>

#include "app_component.h"
#include "controller/xavagent_controller.h"
#include "oatpp/network/Server.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

void run() {
    // ====================== oatpp ======================
    // Register Components in scope of run() method
    xavagent::AppComponent components;

    // Get router component
    OATPP_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, router);

    // Create XavAgentController and add all of its endpoints to router
    router->addController(std::make_shared<xavagent::XavAgentController>());

    // Get connection handler component
    OATPP_COMPONENT(std::shared_ptr<oatpp::network::ConnectionHandler>,
                    connection_handler);

    // Get connection provider component
    OATPP_COMPONENT(std::shared_ptr<oatpp::network::ServerConnectionProvider>,
                    connection_provider);

    // Create server which takes provided TCP connections and passes them to
    // HTTP connection handler
    oatpp::network::Server server(connection_provider, connection_handler);

    // Print info about server port
    OATPP_LOGi("Xav Agent", "Server running on port {}",
               connection_provider->getProperty("port").toString());

    // ====================== boost.beast ======================
    // Configs.
    std::string host = "0.0.0.0";
    std::string port = "8001";

    // The io_context is required for all I/O
    net::io_context ioc;

    // These objects perform our I/O
    tcp::resolver resolver{ioc};
    websocket::stream<tcp::socket> ws{ioc};

    // Look up the domain name
    auto const results = resolver.resolve(host, port);

    // Make the connection on the IP address we get from a lookup
    auto ep = net::connect(ws.next_layer(), results);

    // Update the host_ string. This will provide the value of the
    // Host HTTP header during the WebSocket handshake.
    // See https://tools.ietf.org/html/rfc7230#section-5.4
    host += ':' + std::to_string(ep.port());

    // Set a decorator to change the User-Agent of the handshake
    ws.set_option(
        websocket::stream_base::decorator([](websocket::request_type& req) {
            req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " websocket-client-coro");
        }));

    // Perform the websocket handshake
    ws.handshake(host, "/ws");

    // Send the message
    ws.write(
        net::buffer(std::string("Hello, websocket! This is agent speaking")));

    // This buffer will hold the incoming message
    beast::flat_buffer buffer;

    // Read a message into our buffer
    ws.read(buffer);

    // Close the WebSocket connection
    ws.close(websocket::close_code::normal);

    // If we get here then the connection is closed gracefully

    // The make_printable() function helps print a ConstBufferSequence
    std::cout << beast::make_printable(buffer.data()) << std::endl;

    // Run server
    server.run();
}

int run_main(int argc, const char* argv[]) {
    oatpp::Environment::init();

    run();

    oatpp::Environment::destroy();

    return 0;
}

void sigsegv_handler(int signum) {
    std::cerr << "SIGSEGV signal received" << std::endl;
    cpptrace::generate_trace().print();
    std::exit(signum);
}

int main(int argc, const char* argv[]) {
    std::signal(SIGSEGV, sigsegv_handler);
    try {
        return run_main(argc, argv);
    } catch (std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        cpptrace::generate_trace().print();
        exit(EXIT_FAILURE);
    }
}
