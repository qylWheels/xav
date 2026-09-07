// Trigger program for the proc_kcore_read_rule:
// reads /proc/kcore.
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    int fd = ::open("/proc/kcore", O_RDONLY);
    if (fd < 0) {
        std::cerr << "open /proc/kcore failed" << std::endl;
        return 1;
    }
    char buf[64] = {0};
    (void)::read(fd, buf, sizeof(buf));
    ::close(fd);
    return 0;
}
