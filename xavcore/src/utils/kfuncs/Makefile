# Kernel build entry point for the xavcore_kfuncs out-of-tree module.
#
# This file is invoked twice in two different ways:
#   1. Directly by KBuild during a normal build:
#        make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules
#   2. By DKMS (dkms.conf MAKE below) to build against the target kernel:
#        make -C ${kernel_source_dir} M=${dkms_tree}/<pkg>/<ver>/build
#
# `xavcore_kfuncs.c` lives in the same directory, so a bare obj-m target is
# all KBuild needs to discover and compile it.

KERNEL_MODULE_NAME := xavcore_kfuncs

obj-m += $(KERNEL_MODULE_NAME).o

# Matches the flags the old CMake-driven build used.
ccflags-y := -g

all:
	+$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	+$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
