// Trigger program for the proc_mem_code_injection_rule:
// writes to /proc/<pid>/mem.
#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <iostream>

int main(int argc, char* argv[]) {
    pid_t pid = (argc > 1) ? static_cast<pid_t>(::atoi(argv[1]))
                           : static_cast<pid_t>(::getppid());
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = ::open(path, O_WRONLY);
    if (fd < 0) {
        std::cerr << "open " << path << " failed" << std::endl;
        return 1;
    }
    char data = 0x90;
    (void)::write(fd, &data, 1);
    ::close(fd);
    return 0;
}
