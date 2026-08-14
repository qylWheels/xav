#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("qylWheels");
MODULE_DESCRIPTION("Customized kfuncs for ebpf programs in xavcore");

static int __init xavcore_kfuncs_init(void) {
    printk(KERN_INFO "xavcore kfuncs module init\n");
    return 0;
}

static void __exit xavcore_kfuncs_exit(void) {
    printk(KERN_INFO "xavcore kfuncs module exit\n");
}

module_init(xavcore_kfuncs_init);
module_exit(xavcore_kfuncs_exit);
