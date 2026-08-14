#include "vmlinux.h"

// XXX: vmlinux.h must be at top.

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xavcore/protection/proactive_protection/event_provider/syscall_event_provider/raw_syscall_event.h"

#define PREFIX "xavcore syscall event provider: "

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

int print_path_of_write(int fd) {
    if (fd < 3) {
        return -1;
    }

    int result;

    bpf_printk(PREFIX "[%s] entered", __func__);
    bpf_printk(PREFIX "[%s] fd: %d", __func__, fd);

    struct task_struct* task = bpf_get_current_task_btf();
    struct file** files = BPF_CORE_READ(task, files, fdt, fd);
    if (files == NULL) {
        return -1;
    }
    bpf_printk(PREFIX "[%s] file *[]: %p", __func__, files);

    struct file* file_struct_of_fd = NULL;
    result = bpf_probe_read_kernel(&file_struct_of_fd,
                                   sizeof(file_struct_of_fd), files + fd);
    if (result != 0) {
        return -1;
    }
    bpf_printk(PREFIX "[%s] file_struct_of_fd: %p", __func__,
               file_struct_of_fd);

    const unsigned char* name =
        BPF_CORE_READ(file_struct_of_fd, f_path.dentry, d_name.name);
    if (name == NULL) {
        return -1;
    }
    bpf_printk(PREFIX "[%s] name ptr: %p", __func__, name);
    bpf_printk(PREFIX "[%s] name: %s", __func__, name);

    char path[256] = {0};
    result = bpf_probe_read_kernel_str(path, sizeof(path), name);
    if (result < 0) {
        return -1;
    }
    bpf_printk(PREFIX "[%s] path: %s", __func__, path);

    return 0;
}

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

    if (e.syscall_id == 1) {
        print_path_of_write(e.args[0]);
    }

    // Store the event in the percpu map.
    bpf_map_update_elem(&raw_syscall_event_map, &tid, &e, BPF_ANY);

    return 0;
}

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
        bpf_ringbuf_output(&rb, &e2, sizeof(e2), 0);
        return 0;
    }
    e->exit_captured = 1;
    e->ret = ctx->ret;
    bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
    bpf_map_delete_elem(&raw_syscall_event_map, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
