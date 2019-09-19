obj-m := mac80211_hwsim.o

all:
	$(MAKE) -C "/lib/modules/$(shell uname -r)/build" M=$(shell pwd) modules
clean:
	rm -rf deps.h *.o *.o.ur-safe *.ko *.mod.c *.symvers *.order .*.cmd .tmp_versions
