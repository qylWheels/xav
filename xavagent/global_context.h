#pragma once

#include <leveldb/db.h>
#include <spdlog/spdlog.h>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <memory>

#include "edr/behavioral_protection/behavior_monitor.h"
#include "edr/hash_engine/exact_hash.h"
#include "edr/heuristic_engine/static_heuristic.h"
#include "edr/on_access_protection/on_access_scanner.h"
#include "edr/scanner/scanner.h"

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

    leveldb::DB* db() { return this->db_; }

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
    leveldb::DB* db_;
};
}  // namespace xavagent
