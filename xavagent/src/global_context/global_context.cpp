#include "xavagent/global_context/global_context.h"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>

namespace xavagent {
GlobalContext::GlobalContext(net::io_context& ioc)
    : ws_(net::make_strand(ioc)) {}

GlobalContext& GlobalContext::get_global_context() {
    static net::io_context ioc;
    static GlobalContext instance(ioc);
    return instance;
}

Scanner& GlobalContext::scanner() { return this->scanner_; }

OnAccessScanner& GlobalContext::on_access_scanner() {
    return this->on_access_scanner_;
}

BehaviorMonitorManager& GlobalContext::behavior_monitor() {
    return this->behavior_monitor_;
}

ExactHashEngine& GlobalContext::exact_hash_engine() {
    return this->exact_hash_engine_;
}

StaticHeuristicEngineManager& GlobalContext::static_heur_engine_manager() {
    return this->static_heur_engine_manager_;
}

websocket::stream<tcp::socket>& GlobalContext::ws() { return this->ws_; }

httplib::Server& GlobalContext::httpserver() { return this->httpserver_; }
}  // namespace xavagent
