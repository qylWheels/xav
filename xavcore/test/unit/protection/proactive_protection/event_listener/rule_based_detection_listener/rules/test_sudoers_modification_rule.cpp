// Trigger program for the sudoers_modification_rule:
// writes to /etc/sudoers and renames a file inside /etc/sudoers.d/.
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    // Direct modification of /etc/sudoers (requires root; a failing write to a
    // temp sudoers-like path under /tmp also triggers the path-based rule).
    int fd = ::open("/etc/sudoers", O_WRONLY | O_APPEND);
    if (fd < 0) {
        std::cerr << "open /etc/sudoers failed" << std::endl;
    } else {
        (void)::write(fd, "# modified\n", 11);
        ::close(fd);
    }

    // Rename operation involving /etc/sudoers.d/.
    const char* path = "/etc/sudoers.d/90-test";
    fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        std::cerr << "open " << path << " failed" << std::endl;
        return 1;
    }
    ::close(fd);
    (void)::rename(path, "/etc/sudoers.d/90-test.bak");
    return 0;
}
