EXTRA_CFLAGS += -I$(src) -Wno-error=implicit-int -Wno-int-conversion
EXTRA_CFLAGS += -Wall -Wformat -Wformat-security -Werror=format-security -D_FORTIFY_SOURCE=2 -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

GCCVERBG8 := $(shell expr `gcc --version | grep ^gcc | cut -d " " -f 4` \>= 8.0)
GCCVERBG4 := $(shell expr `gcc --version | grep ^gcc | cut -d " " -f 4` \>= 4.9)

ifeq "$(GCCVERBG8)" "1"
        EXTRA_CFLAGS += -fstack-clash-protection -fcf-protection=full
endif

ifeq "$(GCCVERBG4)" "1"
        EXTRA_CFLAGS += -fstack-protector-strong
endif


obj-m := ashmem_module.o
ashmem_module-y := deps.o ashmem.o

KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KERNEL_SRC) V=0 M=$$PWD

install:
	insmod ashmem_module.ko

clean:
	rm -rf deps.h *.o *.mod.c *.symvers *.order .*.cmd .tmp_versions
