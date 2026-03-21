MODULE_NAME := relm
obj-m := $(MODULE_NAME).o

ccflags-y := -I$(src)

$(MODULE_NAME)-y := \
    src/module.o                  \
    src/vm.o                      \
    src/vmx.o                     \
    src/vmx_asm.o                 \
    src/vmexit.o                  \
    src/ept.o                     \
    src/apic.o                    \
    kernel/guest_kernel_embed.o

AS      ?= $(CROSS_COMPILE)as
OBJCOPY ?= $(CROSS_COMPILE)objcopy

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

.PHONY: all modules clean

all: modules

modules: kernel/guest_kernel.bin
	$(MAKE) -C $(KDIR) M=$(PWD) modules

kernel/guest_kernel.o: kernel/guest_kernel.S
	$(AS) --64 -o $@ $<

kernel/guest_kernel.bin: kernel/guest_kernel.o
	$(OBJCOPY) --output-target binary $< $@

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f kernel/guest_kernel.o \
	      kernel/guest_kernel.bin
