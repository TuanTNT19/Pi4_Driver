EXTRA_CFLAGS=-Wall
obj-m := ssd1306_oled_driver.o
ssd1306_oled_driver-objs = ssd1306_lib.o ssd1306_driver.o

all:
	make ARCH=$(ARCH) CROSS_COMPILE=$(TOOLCHAIN) -C $(KERNEL) M=$(shell pwd) modules
clean:
	make -C $(KERNEL) M=$(shell pwd) clean
