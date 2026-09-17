add_library(sandbox SHARED)
target_sources(
    sandbox
    PRIVATE
    sandbox.cpp
    seccomp_notifier.cpp
)
target_link_libraries(
    sandbox
    PUBLIC
    xavcore_includes outcome::hl
    PkgConfig::SECCOMP
)
