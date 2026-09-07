// Trigger program for the system_request_key_mod_rule:
// writes to the SysRq configuration entry points.
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    // Read first.
    int fd = ::open("/proc/sys/kernel/sysrq", O_RDWR);
    if (fd < 0) {
        std::cerr << "open /proc/sys/kernel/sysrq failed" << std::endl;
        return 1;
    }
    char buf[1024] = {0};
    int ret = ::read(fd, buf, sizeof(buf));
    if (ret < 0) {
        std::cerr << "read /proc/sys/kernel/sysrq failed" << std::endl;
        return 1;
    }
    ::close(fd);

    // Enable sysrq (/proc/sys/kernel/sysrq). Requires root; a failing write
    // still issues the write syscall on the config path.
    int len = ret;
    (void)::write(fd, buf, len);
    ::close(fd);

    // Trigger a kernel command (/proc/sysrq-trigger). Requires root.
    fd = ::open("/proc/sysrq-trigger", O_WRONLY);
    if (fd < 0) {
        std::cerr << "open /proc/sysrq-trigger failed" << std::endl;
        return 1;
    }
    // 'h' = help: harmless read-only help command.
    (void)::write(fd, "h\n", 2);
    ::close(fd);
    return 0;
}
