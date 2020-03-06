EXTRA_CFLAGS += -I$(src) -Wno-int-conversion -Wno-error=incompatible-pointer-types
EXTRA_CFLAGS += -Wall -Wformat -Wformat-security -Werror=format-security -D_FORTIFY_SOURCE=2 -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

GCCVERBG8 := $(shell expr `gcc --version | grep ^gcc | cut -d " " -f 4` \>= 8.0)
GCCVERBG4 := $(shell expr `gcc --version | grep ^gcc | cut -d " " -f 4` \>= 4.9)

ifeq "$(GCCVERBG8)" "1"
        EXTRA_CFLAGS += -fstack-clash-protection -fcf-protection=full
endif

ifeq "$(GCCVERBG4)" "1"
        EXTRA_CFLAGS += -fstack-protector-strong
endif

ifndef CONFIG_ANDROID_BINDER_DEVICES
        EXTRA_CFLAGS += -DCONFIG_ANDROID_BINDER_DEVICES="\"hostbinder,hostvndbinder,hosthwbinder\""
endif
ifndef CONFIG_ANDROID_BINDERFS
        EXTRA_CFLAGS += -DCONFIG_ANDROID_BINDERFS
endif

obj-m := binderfs_module.o binder_module.o
binder_module-y := deps.o binder.o binder_alloc.o
binderfs_module-y := deps.o binderfs.o

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KERNEL_SRC) V=0 M=$$PWD

install:
	insmod binder_module.ko
	insmod binderfs_module.ko
clean:
	rm -rf *.o *.mod.c *.symvers *.order .*.cmd .tmp_versions *.ur-safe
