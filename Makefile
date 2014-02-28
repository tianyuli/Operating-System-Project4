#Name: Xi Wen (xwen) && Tianyu Li (tli) && Xia Li (xli2)
obj-m := mailbox_LKM.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make clean
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$ sudo rmmod mailbox_LKM.ko
	$ sudo insmod mailbox_LKM.ko
	cd P*; ./testmailbox1; tail -n 100 /var/log/syslog
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
