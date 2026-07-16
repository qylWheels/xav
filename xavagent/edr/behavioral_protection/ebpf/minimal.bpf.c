#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    int syscall_id = ctx->id;
    long ret_val = ctx->ret;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    bpf_printk("PID %d (%s): %d sys_exit returned %ld\n", 
                pid, comm, syscall_id, ret_val);
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
