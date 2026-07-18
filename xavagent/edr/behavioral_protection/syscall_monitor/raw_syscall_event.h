#pragma once

struct RawSyscallEvent {
    long long pid;
    long int syscall_id;
    long unsigned int args[6];
    long ret;
};
