#include "xavagent/edr/behavioral_protection/ebpf/syscall_monitor.h"

#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include "syscall_monitor.skel.h"
#include "xavagent/edr/behavioral_protection/syscall_monitor/ebpf/raw_syscall_event.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

static int print_event(void *ctx, void *data, size_t size) {
    struct RawSyscallEvent *e = static_cast<struct RawSyscallEvent *>(data);
    printf(
        "pid: %lld, syscall_id: %ld, args: 0x%p, 0x%p, 0x%p, 0x%p, 0x%p, "
        "0x%p\n",
        e->pid, e->syscall_id, (void *)e->args[0], (void *)e->args[1],
        (void *)e->args[2], (void *)e->args[3], (void *)e->args[4],
        (void *)e->args[5]);
    return 0;
}

int main(int argc, char **argv) {
    struct syscall_monitor_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = syscall_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = minimal_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = minimal_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    struct ring_buffer *rb = NULL;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), print_event, NULL, NULL);

    while (true) {
        int err = ring_buffer__poll(rb, 1000);
        if (err < 0) {
            break;
        }
    }

    ring_buffer__free(rb);

cleanup:
    minimal_bpf__destroy(skel);
    return -err;
}
