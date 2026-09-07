// Trigger program for the proc_mem_access_rule:
// reads /proc/<pid>/mem of another process (the trigger itself when run
// under a monitor; typically you point at a target pid via argv).
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
    int fd = ::open(path, O_RDONLY);
    if (fd < 0) {
        std::cerr << "open " << path << " failed" << std::endl;
        return 1;
    }
    char buf[64] = {0};
    (void)::read(fd, buf, sizeof(buf));
    ::close(fd);
    return 0;
}
