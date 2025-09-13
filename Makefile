EXTRA_CFLAGS=-Wall
obj-m := Netfilter_hook.o

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(TOOLCHAIN) -C $(KERNEL) M=$(BUILDING) modules
clean:
	make -C $(KERNEL) M=$(BUILDING) clean