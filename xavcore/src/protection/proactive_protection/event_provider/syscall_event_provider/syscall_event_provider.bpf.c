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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, u32);
    __type(value, u8[MAX_PATH_LEN + 5]);
} pathbufs SEC(".maps");

extern int bpf_xavcore_get_proc_cwd(char* buf, u64 buf__sz) __ksym;
extern int bpf_xavcore_fd_to_path_str(char* buf, u64 buf__sz, int fd) __ksym;
extern u64 bpf_xavcore_strlen(const char* str) __ksym;
extern u64 bpf_xavcore_strnlen_user(u64 str, u64 max_len) __ksym;
extern s64 bpf_xavcore_strscpy(char* dest, u64 src, u64 dest__sz) __ksym;
extern s64 bpf_xavcore_strncpy_from_user(char* dest, u64 unsafe_src,
                                         u64 dest__sz) __ksym;

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

    // close() must be handled in sys_enter.
    switch (ctx->id) {
        case SYS_close: {
            u32 zero = 0;
            u8* pathbuf0 = (u8*)bpf_map_lookup_elem(&pathbufs, &zero);
            if (!pathbuf0) {
                e.additional_data_count = 0;
                break;
            }

            int result = bpf_xavcore_fd_to_path_str((char*)pathbuf0,
                                                    MAX_PATH_LEN, e.args[0]);
            if (result != 0) {
                e.additional_data_count = 0;
                break;
            }

            e.additional_data_count = 1;
            break;
        }
        case SYS_unlink: {
            u32 zero = 0;
            u8* pathbuf0 = (u8*)bpf_map_lookup_elem(&pathbufs, &zero);
            if (!pathbuf0) {
                e.additional_data_count = 0;
                break;
            }

            if (bpf_xavcore_strncpy_from_user((char*)pathbuf0, e.args[0],
                                              MAX_PATH_LEN) < 0) {
                e.additional_data_count = 0;
                break;
            }

            e.additional_data_count = 1;
            break;
        }
        default: {
            e.additional_data_count = 0;
            break;
        }
    }

exit_if:
    // Store the event in the percpu map.
    bpf_map_update_elem(&raw_syscall_event_map, &tid, &e, BPF_ANY);

    return 0;
}

#define GENERATE_FD_TO_PATH_STR_CODE(pathbuf_index, fd, e)             \
    u32 _i = pathbuf_index;                                            \
    char* _pathbuf = (char*)bpf_map_lookup_elem(&pathbufs, &_i);       \
    if (!_pathbuf) {                                                   \
        e->additional_data_count = 0;                                  \
        bpf_ringbuf_output(&rb, e, sizeof(*e), 0);                     \
        break;                                                         \
    }                                                                  \
                                                                       \
    if (bpf_xavcore_fd_to_path_str(_pathbuf, MAX_PATH_LEN, fd) != 0) { \
        e->additional_data_count = 0;                                  \
        bpf_ringbuf_output(&rb, e, sizeof(*e), 0);                     \
        break;                                                         \
    }

#define GENERATE_RINGBUF_RESERVE_DYNPTR_CODE(pathbuf, e)                       \
    u64 _len = bpf_xavcore_strlen(pathbuf);                                    \
    _len = (_len > MAX_PATH_LEN) ? MAX_PATH_LEN : _len;                        \
                                                                               \
    struct bpf_dynptr _dynptr;                                                 \
    if (bpf_ringbuf_reserve_dynptr(&rb, sizeof(*e) + _len + 5, 0, &_dynptr) != \
        0) {                                                                   \
        bpf_ringbuf_discard_dynptr(&_dynptr, 0);                               \
        e->additional_data_count = 0;                                          \
        bpf_ringbuf_output(&rb, e, sizeof(*e), 0);                             \
        break;                                                                 \
    }

#define GENERATE_DYNPTR_WRITE_CODE(dynptr, e, pathbuf, len)                   \
    if (bpf_dynptr_write(&dynptr, sizeof(*e), (void*)pathbuf, len, 0) != 0) { \
        bpf_ringbuf_discard_dynptr(&dynptr, 0);                               \
        e->additional_data_count = 0;                                         \
        bpf_ringbuf_output(&rb, e, sizeof(*e), 0);                            \
        break;                                                                \
    }                                                                         \
                                                                              \
    e->additional_data_count = 1;                                             \
    e->additional_data_lens[0] = len; /* Not include '\0'. */                 \
                                                                              \
    if (bpf_dynptr_write(&dynptr, 0, e, sizeof(*e), 0) != 0) {                \
        bpf_ringbuf_discard_dynptr(&dynptr, 0);                               \
        e->additional_data_count = 0;                                         \
        bpf_ringbuf_output(&rb, e, sizeof(*e), 0);                            \
        break;                                                                \
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
        e2.additional_data_count = 0;
        bpf_ringbuf_output(&rb, &e2, sizeof(e2), 0);
        return 0;
    }

    e->exit_captured = 1;
    e->ret = ctx->ret;

    // Handle specific syscalls who have additional data. i.e. read.
    switch (e->syscall_id) {
        case SYS_read: {
            GENERATE_FD_TO_PATH_STR_CODE(0, e->args[0], e);
            GENERATE_RINGBUF_RESERVE_DYNPTR_CODE(_pathbuf, e);
            GENERATE_DYNPTR_WRITE_CODE(_dynptr, e, _pathbuf, _len);
            bpf_ringbuf_submit_dynptr(&_dynptr, 0);
            break;
        }
        case SYS_write: {
            GENERATE_FD_TO_PATH_STR_CODE(0, e->args[0], e);
            GENERATE_RINGBUF_RESERVE_DYNPTR_CODE(_pathbuf, e);
            GENERATE_DYNPTR_WRITE_CODE(_dynptr, e, _pathbuf, _len);
            bpf_ringbuf_submit_dynptr(&_dynptr, 0);
            break;
        }
        case SYS_open:
        case SYS_creat: {
            u32 zero = 0;
            u8* pathbuf0 = (u8*)bpf_map_lookup_elem(&pathbufs, &zero);
            if (!pathbuf0) {
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            int result = bpf_xavcore_strncpy_from_user(
                (char*)pathbuf0, e->args[0], MAX_PATH_LEN);
            if (result != 0) {
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            u64 len = bpf_xavcore_strlen((const char*)pathbuf0);
            len = (len > MAX_PATH_LEN) ? MAX_PATH_LEN : len;

            struct bpf_dynptr dynptr;
            result = bpf_ringbuf_reserve_dynptr(&rb, sizeof(*e) + len + 5, 0,
                                                &dynptr);
            if (result != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            result =
                bpf_dynptr_write(&dynptr, sizeof(*e), (void*)pathbuf0, len, 0);
            if (result != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            e->additional_data_count = 1;
            e->additional_data_lens[0] = len;  // Not include '\0'.
            result = bpf_dynptr_write(&dynptr, 0, e, sizeof(*e), 0);
            if (result != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            bpf_ringbuf_submit_dynptr(&dynptr, 0);
            break;
        }
        case SYS_openat:
        case SYS_openat2: {
            u32 zero = 0, one = 1, two = 2;
            char* pathbuf0 = (char*)bpf_map_lookup_elem(&pathbufs, &zero);
            char* pathbuf1 = (char*)bpf_map_lookup_elem(&pathbufs, &one);
            char* pathbuf2 = (char*)bpf_map_lookup_elem(&pathbufs, &two);
            if (!pathbuf0 || !pathbuf1 || !pathbuf2) {
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            // Path string from dirfd argument.
            if (e->args[0] == AT_CWDFD) {
                if (bpf_xavcore_get_proc_cwd(pathbuf0, MAX_PATH_LEN) != 0) {
                    e->additional_data_count = 0;
                    bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                    break;
                }
            } else {
                if (bpf_xavcore_fd_to_path_str(pathbuf0, MAX_PATH_LEN,
                                               e->args[0]) != 0) {
                    e->additional_data_count = 0;
                    bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                    break;
                }
            }

            // Path string from pathname argument.
            if (bpf_probe_read_user_str(pathbuf1, MAX_PATH_LEN,
                                        (const void*)e->args[1]) < 0) {
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            // Concatenate only if path is relative path.
            if (pathbuf1[0] != '/') {
                BPF_SNPRINTF(pathbuf2, MAX_PATH_LEN, "%s/%s", pathbuf0,
                             pathbuf1);
            } else {
                BPF_SNPRINTF(pathbuf2, MAX_PATH_LEN, "%s", pathbuf1);
            }

            u64 len = bpf_xavcore_strlen(pathbuf2);
            len = (len > MAX_PATH_LEN) ? MAX_PATH_LEN : len;

            struct bpf_dynptr dynptr;
            if (bpf_ringbuf_reserve_dynptr(&rb, sizeof(*e) + len + 5, 0,
                                           &dynptr) != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            if (bpf_dynptr_write(&dynptr, sizeof(*e), pathbuf2, len, 0) != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            e->additional_data_count = 1;
            e->additional_data_lens[0] = len;  // Not include '\0'.
            if (bpf_dynptr_write(&dynptr, 0, e, sizeof(*e), 0) != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            bpf_ringbuf_submit_dynptr(&dynptr, 0);
            break;
        }
        case SYS_close: {
            int result;

            // Failed to get path of fd in trace_sys_enter().
            if (e->additional_data_count == 0) {
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            u32 zero = 0;
            char* pathbuf0 = (char*)bpf_map_lookup_elem(&pathbufs, &zero);
            if (!pathbuf0) {
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            u64 len = bpf_xavcore_strlen(pathbuf0);
            len = (len > MAX_PATH_LEN) ? MAX_PATH_LEN : len;

            struct bpf_dynptr dynptr;
            result = bpf_ringbuf_reserve_dynptr(&rb, sizeof(*e) + len + 5, 0,
                                                &dynptr);
            if (result != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            result =
                bpf_dynptr_write(&dynptr, sizeof(*e), (void*)pathbuf0, len, 0);
            if (result != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            e->additional_data_count = 1;
            e->additional_data_lens[0] = len;  // Not include '\0'.
            result = bpf_dynptr_write(&dynptr, 0, e, sizeof(*e), 0);
            if (result != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            bpf_ringbuf_submit_dynptr(&dynptr, 0);
            break;
        }
        case SYS_unlink: {
            // Failed to get path str in trace_sys_enter().
            if (e->additional_data_count == 0) {
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            u32 zero = 0;
            char* pathbuf0 = (char*)bpf_map_lookup_elem(&pathbufs, &zero);
            if (!pathbuf0) {
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            u64 len = bpf_xavcore_strlen(pathbuf0);
            len = (len > MAX_PATH_LEN) ? MAX_PATH_LEN : len;

            struct bpf_dynptr dynptr;
            if (bpf_ringbuf_reserve_dynptr(&rb, sizeof(*e) + len + 5, 0,
                                           &dynptr) != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            if (bpf_dynptr_write(&dynptr, sizeof(*e), (void*)pathbuf0, len,
                                 0) != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            e->additional_data_count = 1;
            e->additional_data_lens[0] = len;  // Not include '\0'.
            if (bpf_dynptr_write(&dynptr, 0, e, sizeof(*e), 0) != 0) {
                bpf_ringbuf_discard_dynptr(&dynptr, 0);
                e->additional_data_count = 0;
                bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
                break;
            }

            bpf_ringbuf_submit_dynptr(&dynptr, 0);
            break;
        }
        default: {
            e->additional_data_count = 0;
            bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
            break;
        }
    }

    bpf_map_delete_elem(&raw_syscall_event_map, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
