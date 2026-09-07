// Trigger program for the rcd_modification_rule:
// writes to /etc/init.d/ scripts, renames files under a runlevel directory,
// and executes the update-rc.d management tool.
#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

int main() {
    // Direct modification of an init script (requires root).
    const char* init_path = "/etc/init.d/malware";
    int fd = ::open(init_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd >= 0) {
        (void)::write(fd, "#!/bin/sh\n", 10);
        ::close(fd);
    } else {
        std::cerr << "open " << init_path << " failed" << std::endl;
    }

    // Rename a file inside a runlevel directory.
    const char* rc_path = "/etc/rc3.d/S99malware";
    fd = ::open(rc_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        std::cerr << "open " << rc_path << " failed" << std::endl;
        return 1;
    }
    ::close(fd);
    (void)::rename(rc_path, "/etc/rc3.d/K99malware");

    // Running the update-rc.d management tool.
    char* const argv[] = {const_cast<char*>("/usr/sbin/update-rc.d"), nullptr};
    char* const envp[] = {nullptr};
    if (::execve("/usr/sbin/update-rc.d", argv, envp) < 0) {
        std::cerr << "execve update-rc.d failed: " << std::strerror(errno)
                  << std::endl;
    }
    return 0;
}
