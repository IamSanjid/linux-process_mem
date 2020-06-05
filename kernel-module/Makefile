obj-m :=  process_mem_module.o
nl_test-y = process_mem_module.o

THIS_DIR := $(shell pwd)

.PHONY: all
all: process_mem_module.ko

process_mem_module.ko: $(KOBJS) Makefile
	$(MAKE) -C $(KERNEL_DIR) M=$(THIS_DIR) modules c=2

.PHONY: install
install:
	$(MAKE) -C $(KERNEL_DIR) INSTALL_MOD_PATH=$(rootfs) M=$(THIS_DIR) -e modules_install

.PHONY: clean
clean:
	rm -f *.o *.mod *.mod.c *.order *.symvers process_mem_module
	$(MAKE) -C $(KERNEL_DIR) M=$(THIS_DIR) clean
