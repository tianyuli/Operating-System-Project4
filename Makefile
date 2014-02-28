#Name: Xi Wen (xwen) && Tianyu Li (tli) && Xia Li (xli2)
obj-m := mailbox_LKM.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make clean
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$ sudo rmmod mailbox_LKM.ko
	$ sudo insmod mailbox_LKM.ko
	cd P*; ./testmailbox1; tail -n 50 /var/log/syslog
nolog:
	make clean
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$ sudo rmmod mailbox_LKM.ko
	$ sudo insmod mailbox_LKM.ko
	cd P*; ./testmailbox1
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
