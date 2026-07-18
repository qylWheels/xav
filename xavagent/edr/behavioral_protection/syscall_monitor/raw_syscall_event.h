#pragma once

struct RawSyscallEvent {
    char enter_captured;
    char exit_captured;

    long long pid;
    long int syscall_id;
    long unsigned int args[6];
    long ret;
};
