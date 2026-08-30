add_library(
    proactive_protection_rules
    SHARED
    test_rule.cpp anti_debug_rule.cpp core_pattern_modification_rule.cpp
    aslr_inspection_rule.cpp cgroup_notify_on_release_rule.cpp
)

target_link_libraries(
    proactive_protection_rules
    PUBLIC
    xavcore_includes outcome::hl
    spdlog::spdlog
)

target_include_directories(
    proactive_protection_rules
    PUBLIC
    ${BEXT_SML_INCLUDE_DIRS}
)
