MODULE_NAME := relm
obj-m := $(MODULE_NAME).o 

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
SRC_DIR := $(PWD)/src
KERNEL_DIR := $(PWD)/kernel

# Module objects
$(MODULE_NAME)-y := \
    $(SRC_DIR)/module.o \
    $(SRC_DIR)/vm.o \
    $(SRC_DIR)/vmx.o \
    $(SRC_DIR)/vmx_asm.o \
    $(SRC_DIR)/vmexit.o \
    $(SRC_DIR)/ept.o \
	$(SRC_DIR)/apic.o \ 
    $(KERNEL_DIR)/guest_kernel_embed.o  # Embed guest

AS      := $(CROSS_COMPILE)as
OBJCOPY := $(CROSS_COMPILE)objcopy

$(KERNEL_DIR)/guest_kernel.o: $(KERNEL_DIR)/guest_kernel.S
	@echo "  AS      guest_kernel.S"
	$(AS) --64 -o $@ $<

$(KERNEL_DIR)/guest_kernel.bin: $(KERNEL_DIR)/guest_kernel.o
	@echo "  OBJCOPY guest_kernel.o -> guest_kernel.bin"
	$(OBJCOPY) --output-target binary $< $@
	@echo "  GUEST   $(shell wc -c < $@) bytes"

$(obj)/kernel/guest_kernel_embed.o: $(KERNEL_DIR)/guest_kernel.bin

.PHONY: all clean modules

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(KERNEL_DIR)/guest_kernel.o $(KERNEL_DIR)/guest_kernel.bin
