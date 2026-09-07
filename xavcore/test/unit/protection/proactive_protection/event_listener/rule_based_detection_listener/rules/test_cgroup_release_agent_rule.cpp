// Trigger program for the cgroup_release_agent_rule:
// writes to a file whose path matches release_agent.
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    int fd = ::open("/tmp/release_agent", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        std::cerr << "open release_agent failed" << std::endl;
        return 1;
    }
    (void)::write(fd, "/bin/sh\n", 8);
    ::close(fd);
    return 0;
}
