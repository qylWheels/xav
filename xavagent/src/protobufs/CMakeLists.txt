add_library(protobufs SHARED)
target_sources(protobufs PRIVATE malware_info.pb.cpp msg.pb.cpp scan_status.pb.cpp)
target_link_libraries(protobufs protobuf::libprotobuf)
