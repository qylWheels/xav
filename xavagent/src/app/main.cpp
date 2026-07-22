#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <exception>
#include <iostream>
#include <thread>

#include "xavagent/api/run_api_server.h"
#include "xavagent/global_context.h"
#include "xavagent/scan/yara_static_heuristic_engine.h"

namespace http = beast::http;

// FIXME: Only for tests.
#define XAV_EXACT_HASH_DB \
    "/home/qyl/projects/xav/xavdb/db/malware-bazaar-sha256.db"

void sigsegv_handler(int signum) {
    std::cerr << "SIGSEGV signal received" << std::endl;
    cpptrace::generate_trace().print();
    std::exit(signum);
}

void init() {
    // Set up logger.
    auto& logger = xavagent::GlobalContext::get_global_context().logger();
    logger = spdlog::stdout_color_mt("global_context");
    logger->set_level(spdlog::level::info);

    // Websocket configs.
    auto& ws = xavagent::GlobalContext::get_global_context().ws();
    auto& ioc = static_cast<net::io_context&>(ws.get_executor().context());
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

    // Initialize db.
    auto& db = xavagent::GlobalContext::get_global_context().db();
    leveldb::Status status =
        leveldb::DB::Open(leveldb::Options{}, XAV_EXACT_HASH_DB, &db);
    if (!status.ok()) {
        perror("leveldb::DB::Open");
        exit(1);
    }

    // Add Yara static heuristic engine to the manager.
    xavagent::GlobalContext::get_global_context()
        .static_heur_engine_manager()
        .add_engine(std::make_shared<xavagent::YaraStaticHeuristicEngine>());

    // Start protection.
    std::jthread on_access_scanner_thread([]() {
        xavagent::GlobalContext::get_global_context()
            .on_access_scanner()
            .start_monitoring();
    });
    std::jthread behavior_monitor_thread([]() {
        xavagent::GlobalContext::get_global_context()
            .behavior_monitor()
            .start_monitoring();
    });
    on_access_scanner_thread.detach();
    behavior_monitor_thread.detach();
}

int main(int argc, const char* argv[]) {
    std::signal(SIGSEGV, sigsegv_handler);
    try {
        init();
        return xavagent::run_api_server(argc, argv);
    } catch (std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        cpptrace::generate_trace().print();
        exit(EXIT_FAILURE);
    }
}
