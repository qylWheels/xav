// Trigger program for the process_vm_inject_rule:
// calls process_vm_writev.
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

int main() {
    char data[] = "inject";
    struct iovec local = {.iov_base = data, .iov_len = sizeof(data)};
    struct iovec remote = {.iov_base = data, .iov_len = sizeof(data)};
    long ret = ::syscall(SYS_process_vm_writev, static_cast<pid_t>(::getpid()),
                         &local, 1, &remote, 1, 0);
    std::cerr << "process_vm_writev returned " << ret << std::endl;
    return 0;
}
