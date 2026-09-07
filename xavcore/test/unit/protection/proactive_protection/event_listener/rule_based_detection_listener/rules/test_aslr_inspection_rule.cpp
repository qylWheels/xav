// Trigger program for the aslr_inspection_rule:
// accesses /proc/sys/kernel/randomize_va_space.
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    int fd = ::open("/proc/sys/kernel/randomize_va_space", O_RDONLY);
    if (fd < 0) {
        std::cerr << "open randomize_va_space failed" << std::endl;
        return 1;
    }
    char buf[64] = {0};
    (void)::read(fd, buf, sizeof(buf));
    ::close(fd);
    return 0;
}
