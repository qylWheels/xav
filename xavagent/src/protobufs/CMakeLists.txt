add_library(
    protobufs
    OBJECT
    "${CMAKE_SOURCE_DIR}/../xavcommon/malware_info.proto"
    "${CMAKE_SOURCE_DIR}/../xavcommon/msg.proto"
    "${CMAKE_SOURCE_DIR}/../xavcommon/scan_status.proto"
)
target_link_libraries(protobufs PUBLIC protobuf::libprotobuf)
set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")
target_include_directories(protobufs PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")
protobuf_generate(
    TARGET protobufs
    IMPORT_DIRS "${CMAKE_SOURCE_DIR}/../xavcommon"
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
)
