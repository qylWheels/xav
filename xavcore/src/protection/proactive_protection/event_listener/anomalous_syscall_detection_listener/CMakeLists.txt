add_library(
    anomalous_syscall_detection_listener
    SHARED
    anomalous_syscall_detection_listener.cpp
)
target_link_libraries(
    anomalous_syscall_detection_listener
    PUBLIC
    xavcore_includes outcome::hl
)
target_include_directories(
    anomalous_syscall_detection_listener
    PUBLIC
    ${MLPACK_INCLUDE_DIRS}
)
