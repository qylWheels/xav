// Trigger program for the default_loader_modify_rule:
// writes to a path matching .*lib.*ld-.*\.so.* and renames it.
#include <fcntl.h>
#include <unistd.h>

#include <iostream>

int main() {
    const char* path = "/tmp/libexample-ld-preload.so";
    int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        std::cerr << "open loader file failed" << std::endl;
        return 1;
    }
    (void)::write(fd, "x", 1);
    ::close(fd);
    (void)::rename(path, "/tmp/libexample-ld-preload.so.bak");
    return 0;
}
