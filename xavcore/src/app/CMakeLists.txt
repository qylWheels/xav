add_executable(xavcore)
target_sources(xavcore PRIVATE main.cpp)
target_link_libraries(
    xavcore PRIVATE
    xavcore_includes syscall_event_provider placeholder_event_listener
    on_access_scanning
    hips_monitor anomalous_syscall_detection_listener
    rule_based_detection_listener proactive_protection_rules
)
target_link_libraries(xavcore PRIVATE scan)
target_link_libraries(xavcore PRIVATE cpptrace::cpptrace)
target_link_libraries(xavcore PRIVATE spdlog::spdlog)

add_executable(xavcore_proactive_protection_module)
target_sources(
    xavcore_proactive_protection_module
    PRIVATE
    proactive_protection_module.cpp
)
target_link_libraries(
    xavcore_proactive_protection_module
    PRIVATE
    xavcore_includes syscall_event_provider anomalous_syscall_detection_listener
    rule_based_detection_listener proactive_protection_rules
)
target_link_libraries(
    xavcore_proactive_protection_module
    PRIVATE
    Boost::beast cpptrace::cpptrace spdlog::spdlog
)
