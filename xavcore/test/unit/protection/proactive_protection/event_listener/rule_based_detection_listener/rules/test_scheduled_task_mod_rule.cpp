// Trigger program for the scheduled_task_mod_rule:
// writes to a scheduling configuration path (crontab) and renames it, and
// also executes the crontab scheduling tool.
#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

int main() {
    const char* path = "/etc/crontab";
    int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        (void)::write(fd, "# x\n", 4);
        ::close(fd);
    } else {
        std::cerr << "open " << path << " failed" << std::endl;
    }

    // Running the scheduling tool (path ending in /crontab) also triggers.
    char* const argv[] = {const_cast<char*>("/usr/bin/crontab"), nullptr};
    char* const envp[] = {nullptr};
    if (::execve("/usr/bin/crontab", argv, envp) < 0) {
        std::cerr << "execve crontab failed: " << std::strerror(errno)
                  << std::endl;
    }
    return 0;
}
