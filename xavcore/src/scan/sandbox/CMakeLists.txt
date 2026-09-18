add_library(
    xavcore_scan_sandbox
    SHARED
    sandbox.cpp
)
add_library(xavcore::scan::sandbox ALIAS xavcore_scan_sandbox)
target_link_libraries(
    xavcore_scan_sandbox
    PRIVATE
    xavcore_includes
)
target_link_libraries(
    xavcore_scan_sandbox
    PUBLIC
    PkgConfig::UNICORN
    outcome::hl elfio::elfio
)
