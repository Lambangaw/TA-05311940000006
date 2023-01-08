obj-m = chall.o 
KERNEL_VERSION=5.4

all: 
	echo $(OBJECTS)
	make -C ../linux-$(KERNEL_VERSION) ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- M=$(PWD) modules -Wno-incompatible-pointer-types

clean:
	make -C ../linux-$(KERNEL_VERSION) M=$(PWD) clean
