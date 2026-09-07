// Trigger program for the cgroup_notify_on_release_rule:
// writes to a file whose path matches notify_on_release.
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    int fd = ::open("/tmp/notify_on_release", O_WRONLY | O_CREAT | O_TRUNC,
                    0644);
    if (fd < 0) {
        std::cerr << "open notify_on_release failed" << std::endl;
        return 1;
    }
    (void)::write(fd, "1\n", 2);
    ::close(fd);
    return 0;
}
