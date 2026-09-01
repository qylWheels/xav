#include <sys/mman.h>
#include <unistd.h>

#include <cstring>
#include <format>
#include <iostream>

int main(int argc, char* argv[]) {
    int fd = ::memfd_create("hahaha", MFD_CLOEXEC);
    if (fd < 0) {
        std::cerr << std::format("memfd_create failed: {}",
                                 std::strerror(errno))
                  << std::endl;
    }

    int ret =
        ::execve(std::format("/proc/self/fd/{}", fd).c_str(), argv, nullptr);
    if (ret < 0) {
        std::cerr << std::format("execve failed: {}", std::strerror(errno))
                  << std::endl;
    }

    return 0;
}
