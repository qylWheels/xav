// Trigger program for the sched_debug_recon_rule:
// reads /proc/sched_debug or /sys/kernel/debug/sched/debug.
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    const char* paths[] = {"/proc/sched_debug",
                           "/sys/kernel/debug/sched/debug"};
    for (const char* path : paths) {
        int fd = ::open(path, O_RDONLY);
        if (fd < 0) {
            continue;
        }
        char buf[256] = {0};
        (void)::read(fd, buf, sizeof(buf));
        ::close(fd);
        return 0;
    }
    std::cerr << "failed to open sched debug files" << std::endl;
    return 1;
}
