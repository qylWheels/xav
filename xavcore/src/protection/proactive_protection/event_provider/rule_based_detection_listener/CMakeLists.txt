add_library(
    rule_based_detection_listener
    SHARED
    rule_based_detection_listener.cpp
)

target_link_libraries(
    rule_based_detection_listener
    PUBLIC
        xavcore_includes outcome::hl
)
