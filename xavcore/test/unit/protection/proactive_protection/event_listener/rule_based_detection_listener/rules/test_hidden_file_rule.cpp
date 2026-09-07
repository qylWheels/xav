// Trigger program for the hidden_file_rule:
// creates a hidden file (path containing a dot-segment).
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    int fd = ::open("/tmp/.hidden_file", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        std::cerr << "open hidden file failed" << std::endl;
        return 1;
    }
    ::close(fd);
    return 0;
}
