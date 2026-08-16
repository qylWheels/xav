#include "vmlinux.h"

// XXX: vmlinux.h must be at top.

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/raw_syscall_event.h"

#define PREFIX "xavcore syscall event provider: "
#define MAX_PATH_LEN (4096)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, u32);  // tid.
    __type(value, struct RawSyscallEvent);
} raw_syscall_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);  // 1MB
} rb SEC(".maps");

extern int bpf_xavcore_fd_to_path_str(char* buf, u64 buf__sz, int fd) __ksym;
extern u64 bpf_xavcore_strlen(const char* str) __ksym;
extern u64 bpf_xavcore_strnlen_user(u64 str, u64 max_len) __ksym;
extern s64 bpf_xavcore_strscpy(char* dest, u64 src, u64 dest__sz) __ksym;

SEC("tp/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter* ctx) {
    struct RawSyscallEvent e;

    // Get the current process ID and thread ID.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;

    // Get task_struct of the current process.
    struct task_struct* task = bpf_get_current_task_btf();

    // Fill in the event fields.
    e.enter_captured = 1;
    e.exit_captured = 0;
    e.timestamp = bpf_ktime_get_boot_ns();
    e.pid = pid;
    e.proc_start_boottime = task->start_boottime;
    e.syscall_id = ctx->id;
    e.args[0] = ctx->args[0];
    e.args[1] = ctx->args[1];
    e.args[2] = ctx->args[2];
    e.args[3] = ctx->args[3];
    e.args[4] = ctx->args[4];
    e.args[5] = ctx->args[5];

exit_if:
    // Store the event in the percpu map.
    bpf_map_update_elem(&raw_syscall_event_map, &tid, &e, BPF_ANY);

    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, u32);
    __type(value, u8[MAX_PATH_LEN + 5]);
} pathbufs SEC(".maps");

SEC("tp/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit* ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct RawSyscallEvent* e = (struct RawSyscallEvent*)bpf_map_lookup_elem(
        &raw_syscall_event_map, &tid);
    if (!e) {
        struct RawSyscallEvent e2;
        e2.enter_captured = 0;
        e2.exit_captured = 1;
        e2.timestamp = bpf_ktime_get_boot_ns();
        e2.pid = pid;
        struct task_struct* task = bpf_get_current_task_btf();
        e2.proc_start_boottime = task->start_boottime;
        e2.syscall_id = ctx->id;
        e2.ret = ctx->ret;
        e2.additional_str_count = 0;
        bpf_ringbuf_output(&rb, &e2, sizeof(e2), 0);
        return 0;
    }
    e->exit_captured = 1;
    e->ret = ctx->ret;

    switch (e->syscall_id) {
        case 0: {  // read.
            e->additional_str_count = 1;
            u32 zero = 0, one = 1;
            u8* pathbuf0 = (u8*)bpf_map_lookup_elem(&pathbufs, &zero);
            u8* pathbuf1 = (u8*)bpf_map_lookup_elem(&pathbufs, &one);
            if (!pathbuf0 || !pathbuf1) {
                break;
            }
            int result = bpf_xavcore_fd_to_path_str((char*)pathbuf0,
                                                    MAX_PATH_LEN, e->args[0]);
            if (result != 0) {
                break;
            }
            u64 len = bpf_xavcore_strlen((const char*)pathbuf0);
            len = (len > MAX_PATH_LEN) ? MAX_PATH_LEN : len;
            struct bpf_dynptr dynptr;
            result = bpf_ringbuf_reserve_dynptr(&rb, sizeof(*e) + len + 5, 0,
                                                &dynptr);
            if (result != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                break;
            }
            result = bpf_dynptr_write(&dynptr, 0, e, sizeof(*e), 0);
            if (result != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                break;
            }
            result = bpf_dynptr_write(&dynptr, sizeof(*e), (void*)pathbuf0,
                                      len + 1, 0);
            if (result != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                break;
            }
            bpf_ringbuf_submit_dynptr(&dynptr, 0);
            bpf_map_delete_elem(&raw_syscall_event_map, &tid);
            return 0;
        }
        default:
            break;
    }

    bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
    bpf_map_delete_elem(&raw_syscall_event_map, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
