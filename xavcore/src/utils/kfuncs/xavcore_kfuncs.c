#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("qylWheels");
MODULE_DESCRIPTION("Customized kfuncs for ebpf programs in xavcore");

// kfunc prototype.
__bpf_kfunc int bpf_parse_path_struct(char *buf, u64 bufsz, struct path *path);

// Begin kfunc definitions.
__bpf_kfunc_start_defs();

// Define bpf_parse_path_struct kfunc.
__bpf_kfunc int bpf_parse_path_struct(char *buf, u64 bufsz, struct path *path) {
    return 114514;
}

// End kfunc definitions.
__bpf_kfunc_end_defs();

// Define BTF kfuncs IDs set.
BTF_KFUNCS_START(xavcore_kfuncs_ids_set)
BTF_ID_FLAGS(func, bpf_parse_path_struct)
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
