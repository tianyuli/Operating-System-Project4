#Name: Xi Wen (xwen) && Tianyu Li (tli) && Xia Li (xli2)
obj-m := mailbox_LKM.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make clean
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
