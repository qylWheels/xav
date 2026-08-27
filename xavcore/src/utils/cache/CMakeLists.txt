add_library(cache SHARED cache.cpp)
add_library(xavcore::utils::cache ALIAS cache)
target_link_libraries(cache
    PUBLIC
    xavcore_includes
)
target_link_libraries(
    cache
    PUBLIC
    Boost::container_hash
)
