# add_executable(xavcore)
# target_sources(xavcore PRIVATE main.cpp)
# target_link_libraries(
#     xavcore PRIVATE
#     xavcore_includes syscall_event_provider placeholder_event_listener
#     on_access_scanning
#     hips_monitor anomalous_syscall_detection_listener
#     rule_based_detection_listener proactive_protection_rules
# )
# target_link_libraries(xavcore PRIVATE scan)
# target_link_libraries(xavcore PRIVATE cpptrace::cpptrace)
# target_link_libraries(xavcore PRIVATE spdlog::spdlog)

add_executable(xavcore_on_access_scanning_module on_access_scanning_module.cpp)
target_link_libraries(
    xavcore_on_access_scanning_module
    PRIVATE
    xavcore_includes
    on_access_scanning scan
)
target_link_libraries(
    xavcore_on_access_scanning_module
    PRIVATE
    Boost::asio cpptrace::cpptrace spdlog::spdlog
    nlohmann_json::nlohmann_json
)

add_executable(
    xavcore_proactive_protection_module
    proactive_protection_module.cpp
)
target_link_libraries(
    xavcore_proactive_protection_module
    PRIVATE
    xavcore_includes syscall_event_provider
    rule_based_detection_listener
)
target_link_libraries(
    xavcore_proactive_protection_module
    PRIVATE
    Boost::asio cpptrace::cpptrace spdlog::spdlog
)
