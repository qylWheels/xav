add_library(
    proactive_protection_rules
    SHARED
    test_rule.cpp anti_debug_rule.cpp core_pattern_modification_rule.cpp
    aslr_inspection_rule.cpp cgroup_notify_on_release_rule.cpp
    cgroup_release_agent_rule.cpp default_loader_modify_rule.cpp
    dynamic_code_loading_rule.cpp fileless_execution_rule.cpp
    hidden_file_rule.cpp kernel_module_loading_rule.cpp
    process_vm_inject_rule.cpp proc_kcore_read_rule.cpp
    proc_mem_access_rule.cpp
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
