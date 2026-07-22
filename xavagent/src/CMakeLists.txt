# Subdirectories.
add_subdirectory(app)
add_subdirectory(protection)
add_subdirectory(protobufs)
add_subdirectory(scan)

add_library(global_context SHARED)
target_sources(global_context PRIVATE global_context.cpp)
target_link_libraries(
    global_context PUBLIC
    leveldb::leveldb
    spdlog::spdlog
    Boost::beast
)
target_link_libraries(global_context PUBLIC xavagent_includes)
