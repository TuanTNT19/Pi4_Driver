EXTRA_CFLAGS=-Wall
obj-m := timer_test.o

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(TOOLCHAIN) -C $(KERNEL) M=$(BUILDING) modules
clean:
	make -C $(KERNEL) M=$(BUILDING) clean