#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <iostream>
#include <utility>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

int main(int argc, char* argv[]) {
    try {
        // I/O context.
        net::io_context ioc{1};

        // TCP connection.
        tcp::acceptor acceptor{
            ioc, tcp::endpoint(net::ip::make_address("0.0.0.0"), 8000)};
        tcp::socket socket = acceptor.accept();

        // WebSocket connection.
        websocket::stream<tcp::socket> ws(std::move(socket));
        ws.set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res) {
                res.set(http::field::server,
                        "Xavcore Proactive Protection Module");
            }));
        ws.accept();

        // Handle messages from the client
        while (true) {
            ws.write(net::buffer("Hello, World!"));
        }
    } catch (std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return 0;
}
