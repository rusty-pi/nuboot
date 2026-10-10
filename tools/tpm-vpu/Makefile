# Out of tree: make -C /lib/modules/$(uname -r)/build M=$PWD modules
obj-m += tpm_vpu.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
