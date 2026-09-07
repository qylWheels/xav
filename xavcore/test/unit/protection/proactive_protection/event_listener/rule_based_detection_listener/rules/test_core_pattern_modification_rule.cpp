// Trigger program for the core_pattern_modification_rule:
// writes to /proc/sys/kernel/core_pattern.
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    int fd = ::open("/proc/sys/kernel/core_pattern", O_WRONLY);
    if (fd < 0) {
        std::cerr << "open core_pattern failed" << std::endl;
        return 1;
    }
    (void)::write(fd, "core\n", 5);
    ::close(fd);
    return 0;
}
