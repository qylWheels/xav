#pragma once

#include <httplib.h>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#include "xavagent/protection/on_access_scanner.h"
#include "xavagent/scan/exact_hash.h"
#include "xavagent/scan/scanner.h"
#include "xavagent/scan/static_heuristic.h"

namespace beast = boost::beast;
namespace websocket = beast::websocket;
using tcp = boost::asio::ip::tcp;
namespace net = boost::asio;

namespace xavagent {
class GlobalContext {
public:
    ~GlobalContext() = default;

public:
    static GlobalContext& get_global_context();
    Scanner& scanner();
    OnAccessScanner& on_access_scanner();
    ExactHashEngine& exact_hash_engine();
    StaticHeuristicEngineManager& static_heur_engine_manager();
    websocket::stream<tcp::socket>& ws();
    httplib::Server& httpserver();

private:
    GlobalContext(net::io_context& ioc);
    GlobalContext(const GlobalContext&) = delete;
    GlobalContext& operator=(const GlobalContext&) = delete;
    GlobalContext(GlobalContext&&) = delete;
    GlobalContext& operator=(GlobalContext&&) = delete;

private:
    Scanner scanner_;
    OnAccessScanner on_access_scanner_;
    ExactHashEngine exact_hash_engine_;
    StaticHeuristicEngineManager static_heur_engine_manager_;
    websocket::stream<tcp::socket> ws_;
    httplib::Server httpserver_;
};
}  // namespace xavagent
