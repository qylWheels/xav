#include <cpptrace/cpptrace.hpp>
#include <csignal>
#include <exception>
#include <iostream>

#include "api/run_api_server.h"

void sigsegv_handler(int signum) {
    std::cerr << "SIGSEGV signal received" << std::endl;
    cpptrace::generate_trace().print();
    std::exit(signum);
}

int main(int argc, const char* argv[]) {
    std::signal(SIGSEGV, sigsegv_handler);
    try {
        return xavagent::run_api_server(argc, argv);
    } catch (std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        cpptrace::generate_trace().print();
        exit(EXIT_FAILURE);
    }
}
