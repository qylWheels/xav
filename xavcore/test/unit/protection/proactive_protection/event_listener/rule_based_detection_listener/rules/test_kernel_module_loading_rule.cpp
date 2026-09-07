// Trigger program for the kernel_module_loading_rule:
// invokes init_module (kernel module loading).
#include <sys/syscall.h>
#include <unistd.h>

#include <iostream>

int main() {
    char image[1] = {0};
    // Requires root. Even a failing init_module triggers the rule's syscall
    // detection.
    long ret = ::syscall(SYS_init_module, image, sizeof(image), "");
    std::cerr << "init_module returned " << ret << std::endl;
    return 0;
}
