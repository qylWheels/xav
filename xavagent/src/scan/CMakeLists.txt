add_library(scan SHARED)
target_sources(scan
    exact_hash.cpp scanner.cpp
    static_heuristic.cpp yara_static_heuristic_engine.cpp
)
