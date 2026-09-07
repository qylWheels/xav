// Trigger program for the ptrace_code_injection_rule:
// issues ptrace PTRACE_POKETEXT / PTRACE_POKEDATA requests.
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

int main() {
    pid_t child = ::fork();
    if (child == 0) {
        // Child stops so the parent can poke it.
        ::raise(SIGSTOP);
        return 0;
    }
    if (child < 0) {
        std::cerr << "fork failed" << std::endl;
        return 1;
    }

    ::waitpid(child, nullptr, 0);
    if (::ptrace(PTRACE_ATTACH, child, nullptr, nullptr) < 0) {
        std::cerr << "ptrace attach failed: " << std::strerror(errno)
                  << std::endl;
    }
    ::waitpid(child, nullptr, 0);

    unsigned long word = 0x90;
    (void)::ptrace(PTRACE_POKETEXT, child, reinterpret_cast<void*>(0x0), word);
    (void)::ptrace(PTRACE_POKEDATA, child, reinterpret_cast<void*>(0x0), word);

    ::ptrace(PTRACE_DETACH, child, nullptr, nullptr);
    ::kill(child, SIGCONT);
    ::waitpid(child, nullptr, 0);
    return 0;
}
