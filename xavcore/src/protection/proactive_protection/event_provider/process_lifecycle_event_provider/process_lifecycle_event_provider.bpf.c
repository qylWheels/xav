#include "vmlinux.h"

// XXX: vmlinux.h must be at top.

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xavcore/protection/proactive_protection/event_provider/process_lifecycle_event_provider/raw_process_lifecycle_event.h"

#define PREFIX "xavcore process lifecycle event provider: "

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);  // 64KB
} rb SEC(".maps");

SEC("tp/sched/sched_process_fork")
int trace_process_fork(struct trace_event_raw_sched_process_fork* ctx) {
    RawProcessCreateEvent* e = (RawProcessCreateEvent*)bpf_ringbuf_reserve(
        &rb, sizeof(RawProcessCreateEvent), 0);
    if (!e) {
        bpf_printk(PREFIX "[%s] bpf_ringbuf_reserve failed\n", __func__);
        return 0;
    }
    e->pid = ctx->child_pid;
    bpf_ringbuf_submit(&rb, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template* ctx) {
    RawProcessExitEvent* e = (RawProcessExitEvent*)bpf_ringbuf_reserve(
        &rb, sizeof(RawProcessExitEvent), 0);
    if (!e) {
        bpf_printk(PREFIX "[%s] bpf_ringbuf_reserve failed\n", __func__);
        return 0;
    }
    e->pid = ctx->pid;
    bpf_ringbuf_submit(&rb, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
