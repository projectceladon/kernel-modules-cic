ccflags-y += -I$(src) -Wno-int-conversion -Wno-error=incompatible-pointer-types  -DCONFIG_ANDROID_BINDER_DEVICES="\"hostbinder,hostvndbinder,hosthwbinder\"" -DCONFIG_ANDROID_BINDERFS
obj-m := binderfs_module.o binder_module.o
binder_module-y := deps.o binder.o binder_alloc.o
binderfs_module-y := deps.o binderfs.o

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KERNEL_SRC) V=0 M=$$PWD

install:
	cp binder_module.ko $(DESTDIR)/
	cp binderfs_module.ko $(DESTDIR)/
	insmod binder_module.ko
	insmod binderfs_module.ko
clean:
	rm -rf *.o *.ko *.mod.c *.symvers *.order .*.cmd .tmp_versions *.ur-safe
