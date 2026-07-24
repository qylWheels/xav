#pragma once

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <memory>

#include "xavagent/protection/behavior_monitor.h"
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
    static GlobalContext& get_global_context() {
        static net::io_context ioc;
        static GlobalContext instance(ioc);
        return instance;
    }

    Scanner& scanner() { return this->scanner_; }

    OnAccessScanner& on_access_scanner() { return this->on_access_scanner_; }

    BehaviorMonitorManager& behavior_monitor() {
        return this->behavior_monitor_;
    }

    ExactHashEngine& exact_hash_engine() { return this->exact_hash_engine_; }

    StaticHeuristicEngineManager& static_heur_engine_manager() {
        return this->static_heur_engine_manager_;
    }

    websocket::stream<tcp::socket>& ws() { return this->ws_; }

    std::shared_ptr<spdlog::logger>& logger() { return this->logger_; }

    httplib::Server& httpserver() { return this->httpserver_; }

private:
    GlobalContext(net::io_context& ioc);
    ~GlobalContext() = default;
    GlobalContext(const GlobalContext&) = delete;
    GlobalContext& operator=(const GlobalContext&) = delete;
    GlobalContext(GlobalContext&&) = delete;
    GlobalContext& operator=(GlobalContext&&) = delete;

private:
    Scanner scanner_;
    OnAccessScanner on_access_scanner_;
    BehaviorMonitorManager behavior_monitor_;
    ExactHashEngine exact_hash_engine_;
    StaticHeuristicEngineManager static_heur_engine_manager_;
    websocket::stream<tcp::socket> ws_;
    std::shared_ptr<spdlog::logger> logger_;
    httplib::Server httpserver_;
};
}  // namespace xavagent
