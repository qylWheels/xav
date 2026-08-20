#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/delay.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("qylWheels");
MODULE_DESCRIPTION("Customized kfuncs for xavcore BPF LSM module");

__bpf_kfunc_start_defs();

__bpf_kfunc void bpf_xavcore_msleep_if_streq(const char *s1, const char *s2,
                                             u32 ms) {
    if (strcmp(s1, s2) == 0) {
        printk(KERN_INFO "bpf_xavcore_msleep_if_streq: sleep %d ms\n", ms);
        msleep(ms);
        printk(KERN_INFO "bpf_xavcore_msleep_if_streq: end sleep\n");
    }
    return;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(xavcore_lsm_kfuncs_ids_set)
BTF_ID_FLAGS(func, bpf_xavcore_msleep_if_streq)
BTF_KFUNCS_END(xavcore_lsm_kfuncs_ids_set)

// Register kfunc IDs set for LSM.
static const struct btf_kfunc_id_set xavcore_lsm_kfuncs_set = {
    .owner = THIS_MODULE,
    .set = &xavcore_lsm_kfuncs_ids_set,
};

static int __init xavcore_lsm_kfuncs_init(void) {
    int ret;
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &xavcore_lsm_kfuncs_set);
    if (ret) {
        printk(KERN_ERR "Failed to register BTF kfunc ID set for LSM: %d\n",
               ret);
        return ret;
    }
    return 0;
}

static void __exit xavcore_lsm_kfuncs_exit(void) {
    printk(KERN_INFO "xavcore lsm kfuncs module exit successfully\n");
}

module_init(xavcore_lsm_kfuncs_init);
module_exit(xavcore_lsm_kfuncs_exit);
