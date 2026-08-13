import ctypes
import system_calls

libc = ctypes.CDLL("libc.so.6")
NR_PTRACE = system_calls.syscalls()["ptrace"]
PTRACE_TRACEME = 0
result = libc.syscall(NR_PTRACE, PTRACE_TRACEME, 0, 0, 0)
if result == 0:
    print("Process is not being traced")
else:
    print("Process is being traced")
