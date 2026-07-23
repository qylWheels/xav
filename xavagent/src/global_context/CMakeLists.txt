add_library(global_context SHARED)
target_sources(global_context PRIVATE global_context.cpp)
target_link_libraries(
    global_context
    PUBLIC
    protobufs
    leveldb::leveldb
    spdlog::spdlog
    Boost::beast
    httplib::httplib
)
target_link_libraries(global_context PUBLIC xavagent_includes)
