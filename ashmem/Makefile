ccflags-y += -I$(src) -Wno-error=implicit-int -Wno-int-conversion
obj-m := ashmem_module.o
ashmem_module-y := deps.o ashmem.o

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KERNEL_SRC) V=0 M=$$PWD

install:
	cp ashmem_module.ko $(DESTDIR)/

clean:
	rm -rf deps.h *.o *.ko *.mod.c *.symvers *.order .*.cmd .tmp_versions
