// Trigger program for the test_rule (a sample FSM rule):
// issues repeated process_vm_writev calls to drive the FSM into its
// terminal (detected) state.
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <iostream>

int main() {
    char data[] = "x";
    struct iovec local = {.iov_base = data, .iov_len = sizeof(data)};
    struct iovec remote = {.iov_base = data, .iov_len = sizeof(data)};
    for (int i = 0; i < 4; ++i) {
        long ret = ::syscall(SYS_process_vm_writev,
                             static_cast<pid_t>(::getpid()), &local, 1, &remote,
                             1, 0);
        std::cerr << "process_vm_writev #" << i << " returned " << ret
                  << std::endl;
    }
    return 0;
}
