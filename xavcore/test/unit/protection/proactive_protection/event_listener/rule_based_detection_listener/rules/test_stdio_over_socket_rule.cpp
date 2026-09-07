// Trigger program for the stdio_over_socket_rule:
// creates a socket and dup2()s it onto the standard I/O descriptors
// (0/1/2), i.e. the classic reverse-shell redirection.
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

int main() {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "socket() failed: " << std::strerror(errno) << std::endl;
        return 1;
    }
    for (int fd = 0; fd <= 2; ++fd) {
        if (::dup2(sock, fd) < 0) {
            std::cerr << "dup2(" << sock << ", " << fd
                      << ") failed: " << std::strerror(errno) << std::endl;
        }
    }
    // Keep the descriptors open for a moment so a monitor observes them.
    ::sleep(2);
    return 0;
}
