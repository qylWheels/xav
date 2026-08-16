#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("qylWheels");
MODULE_DESCRIPTION("Customized kfuncs for ebpf programs in xavcore");

// kfunc prototype.
__bpf_kfunc int bpf_xavcore_fd_to_path_str(char *buf, u64 buf__sz, int fd);
__bpf_kfunc u64 bpf_xavcore_strlen(u64 str);
__bpf_kfunc u64 bpf_xavcore_strnlen_user(u64 str, u64 max_len);
__bpf_kfunc s64 bpf_xavcore_strscpy(char *dest, u64 src, u64 dest__sz);

// Begin kfunc definitions.
__bpf_kfunc_start_defs();

// Define bpf_parse_path_struct kfunc.
// Run in process context.
__bpf_kfunc int bpf_xavcore_fd_to_path_str(char *buf, u64 buf__sz, int fd) {
    if (!buf) {
        return -EINVAL;
    }

    struct fd f = fdget(fd);
    struct file *file = fd_file(f);

    if (!file) {
        return -EFAULT;
    }

    struct path *path = &file->f_path;
    char *result = d_path(path, buf, buf__sz);
    if (IS_ERR_OR_NULL(result)) {
        return -EFAULT;
    }

    fdput(f);

    // Copy result string to the begin of the buffer.
    // May overlapped.
    memmove(buf, result, strlen(result) + 1);

    return 0;
}

__bpf_kfunc u64 bpf_xavcore_strlen(u64 str) {
    return strlen((const char *)str);
}

__bpf_kfunc u64 bpf_xavcore_strnlen_user(u64 str, u64 max_len) {
    return strnlen_user((const char *)str, max_len);
}

__bpf_kfunc s64 bpf_xavcore_strscpy(char *dest, u64 src, u64 dest__sz) {
    return strscpy(dest, (const char *)src, dest__sz);
}

// End kfunc definitions.
__bpf_kfunc_end_defs();

// Define BTF kfuncs IDs set.
BTF_KFUNCS_START(xavcore_kfuncs_ids_set)
BTF_ID_FLAGS(func, bpf_xavcore_fd_to_path_str)
BTF_ID_FLAGS(func, bpf_xavcore_strlen)
BTF_ID_FLAGS(func, bpf_xavcore_strnlen_user)
BTF_ID_FLAGS(func, bpf_xavcore_strscpy)
BTF_KFUNCS_END(xavcore_kfuncs_ids_set)

// Register kfunc IDs set.
static const struct btf_kfunc_id_set xavcore_kfuncs_set = {
    .owner = THIS_MODULE,
    .set = &xavcore_kfuncs_ids_set,
};

static int __init xavcore_kfuncs_init(void) {
    int ret;

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACEPOINT,
                                    &xavcore_kfuncs_set);
    if (ret) {
        printk(KERN_ERR "Failed to register BTF kfunc ID set: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "xavcore kfuncs module init successfully\n");
    return 0;
}

static void __exit xavcore_kfuncs_exit(void) {
    printk(KERN_INFO "xavcore kfuncs module exit successfully\n");
}

module_init(xavcore_kfuncs_init);
module_exit(xavcore_kfuncs_exit);
