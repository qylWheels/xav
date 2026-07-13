#pragma once

#include "xavagent/edr/behavioral_protection/behavior_monitor.h"
#include "xavagent/edr/on_access_scanner.h"
#include "xavagent/edr/scanner.h"
#include "xavlib/exact_hash.h"
#include "xavlib/heuristic/static_heuristic.h"
#include "xavlib/heuristic/yara_static_heuristic_engine.h"

namespace xavagent {
class GlobalContext;

class GlobalContext {
public:
    static GlobalContext& get_global_context() {
        static GlobalContext instance;
        return instance;
    }

    Scanner& scanner() { return this->scanner_; }

    OnAccessScanner& on_access_scanner() { return this->on_access_scanner_; }

    BehaviorMonitor& behavior_monitor() { return this->behavior_monitor_; }

    xavlib::ExactHashEngine& exact_hash_engine() {
        return this->exact_hash_engine_;
    }

    xavlib::StaticHeuristicEngineManager& static_heur_engine_manager() {
        return this->static_heur_engine_manager_;
    }

private:
    GlobalContext() {
        this->static_heur_engine_manager_.add_engine(
            std::make_shared<xavlib::YaraStaticHeuristicEngine>());
    }

    ~GlobalContext() = default;
    GlobalContext(const GlobalContext&) = delete;
    GlobalContext& operator=(const GlobalContext&) = delete;
    GlobalContext(GlobalContext&&) = delete;
    GlobalContext& operator=(GlobalContext&&) = delete;

private:
    Scanner scanner_;
    OnAccessScanner on_access_scanner_;
    BehaviorMonitor behavior_monitor_;
    xavlib::ExactHashEngine exact_hash_engine_;
    xavlib::StaticHeuristicEngineManager static_heur_engine_manager_;
};
}  // namespace xavagent
