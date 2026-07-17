#include "global_context.h"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>
#include <thread>

#include "edr/heuristic_engine/yara_static_heuristic_engine.h"

namespace http = beast::http;

// FIXME: Only for tests.
#define XAV_EXACT_HASH_DB \
    "/home/qyl/projects/xav/xavdb/db/malware-bazaar-sha256.db"

namespace xavagent {
GlobalContext::GlobalContext(net::io_context& ioc)
    : ws_(net::make_strand(ioc)) {
    // Set up logger.
    this->logger_ = spdlog::stdout_color_mt("global_context");
    this->logger_->set_level(spdlog::level::info);

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

    // Start a thread to read from websocket to handle ping frame.
    std::jthread ws_read_thread([this]() {
        while (true) {
            beast::flat_buffer buffer;
            this->ws_.read(buffer);
        }
    });
    ws_read_thread.detach();

    // Initialize db.
    leveldb::Status status =
        leveldb::DB::Open(leveldb::Options{}, XAV_EXACT_HASH_DB, &this->db_);
    if (!status.ok()) {
        perror("leveldb::DB::Open");
        exit(1);
    }

    // Add Yara static heuristic engine to the manager.
    this->static_heur_engine_manager_.add_engine(
        std::make_shared<YaraStaticHeuristicEngine>());
}
}  // namespace xavagent
