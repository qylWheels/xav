// Trigger program for the anti_debug_rule:
// calls ptrace(PTRACE_TRACEME), which the rule detects.
#include <sys/ptrace.h>

#include <cerrno>
#include <cstring>
#include <iostream>

int main() {
    if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
        std::cerr << "ptrace(PTRACE_TRACEME) failed: " << std::strerror(errno)
                  << std::endl;
    }
    return 0;
}
