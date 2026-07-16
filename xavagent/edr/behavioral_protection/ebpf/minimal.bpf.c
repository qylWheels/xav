#include "vmlinux.h"

// XXX: vmlinux.h must be at top.

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xavagent/edr/behavioral_protection/ebpf/raw_syscall_event.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);  // 1MB
} rb SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter* ctx) {
    struct RawSyscallEvent* e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        // Let it go.
        return 0;
    }

    // Fill in the event fields.
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->syscall_id = ctx->id;
    e->args[0] = ctx->args[0];
    e->args[1] = ctx->args[1];
    e->args[2] = ctx->args[2];
    e->args[3] = ctx->args[3];
    e->args[4] = ctx->args[4];
    e->args[5] = ctx->args[5];

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
