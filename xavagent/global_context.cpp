#include "global_context.h"

#include "xavlib/heuristic/yara_static_heuristic_engine.h"

namespace http = beast::http;

namespace xavagent {
GlobalContext::GlobalContext(net::io_context& ioc) : ws_(ioc) {
    // Websocket configs.
    std::string host = "0.0.0.0";
    std::string port = "8001";
    tcp::resolver resolver{ioc};
    auto const results = resolver.resolve(host, port);
    auto ep = net::connect(this->ws_.next_layer(), results);
    host += ':' + std::to_string(ep.port());
    this->ws_.set_option(
        websocket::stream_base::decorator([](websocket::request_type& req) {
            req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " websocket-client-coro");
        }));
    this->ws_.binary(true);
    this->ws_.handshake(host, "/ws");

    // Add Yara static heuristic engine to the manager.
    this->static_heur_engine_manager_.add_engine(
        std::make_shared<xavlib::YaraStaticHeuristicEngine>());
}
}  // namespace xavagent
