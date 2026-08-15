#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/fdtable.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("qylWheels");
MODULE_DESCRIPTION("Customized kfuncs for ebpf programs in xavcore");

// kfunc prototype.
__bpf_kfunc int bpf_fd_to_path_str(char *buf, u64 buf__sz,
                                   struct task_struct *task, int fd,
                                   u64 *result_ptr_addr);
__bpf_kfunc size_t bpf_xavcore_strlen(const char *str);

// Begin kfunc definitions.
__bpf_kfunc_start_defs();

// Define bpf_parse_path_struct kfunc.
__bpf_kfunc int bpf_fd_to_path_str(char *buf, u64 buf__sz,
                                   struct task_struct *task, int fd,
                                   u64 *result_ptr_addr) {
    if (!buf || !task || !result_ptr_addr) {
        return -EINVAL;
    }

    struct files_struct *files = task->files;
    if (!files) {
        return -EFAULT;
    }

    rcu_read_lock();

    struct fdtable *fdt = rcu_dereference(files->fdt);
    if (!fdt) {
        return -EFAULT;
    }

    struct file **fds = rcu_dereference(fdt->fd);
    if (!fds) {
        return -EFAULT;
    }

    struct file *file = fds[fd];
    if (!file) {
        return -EFAULT;
    }

    rcu_read_unlock();

    struct path *path = &file->f_path;

    *result_ptr_addr = (u64)d_path(path, buf, buf__sz);

    return 0;
}

__bpf_kfunc size_t bpf_xavcore_strlen(const char *str) { return strlen(str); }

// End kfunc definitions.
__bpf_kfunc_end_defs();

// Define BTF kfuncs IDs set.
BTF_KFUNCS_START(xavcore_kfuncs_ids_set)
BTF_ID_FLAGS(func, bpf_fd_to_path_str)
BTF_ID_FLAGS(func, bpf_xavcore_strlen)
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
