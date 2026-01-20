MODULE_NAME := relm
obj-m := $(MODULE_NAME).o 

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Defining the objects that make up the module
$(MODULE_NAME)-y := \
	src/module.o \
	src/vm.o \
	src/vmx.o \
	src/vmx_asm.o \
	src/vmexit.o \
	src/ept.o

# ccflags-y adds include directories
ccflags-y := -I$(src)/include -I$(src)/utils

.PHONY: all clean modules

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
