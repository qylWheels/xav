#pragma once

#include "event.h"

class BehaviorMonitor {
public:
    BehaviorMonitor();
    ~BehaviorMonitor();
    BehaviorMonitor(const BehaviorMonitor&) = delete;
    BehaviorMonitor& operator=(const BehaviorMonitor&) = delete;
    BehaviorMonitor(BehaviorMonitor&&) = delete;
    BehaviorMonitor& operator=(BehaviorMonitor&&) = delete;

public:
    void start_monitor();
    void stop_monitor();
};
