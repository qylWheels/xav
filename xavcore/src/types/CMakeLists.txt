# Subdirectories.
add_library(types SHARED file_fingerprint.cpp)
add_library(xavcore::types ALIAS types)
target_link_libraries(types PUBLIC xavcore_includes)
target_link_libraries(
    types
    PRIVATE
    boost_container_hash
)
