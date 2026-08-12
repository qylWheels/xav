add_library(
    proactive_protection_rules
    SHARED
    test_rule.cpp
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
