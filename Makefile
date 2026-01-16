MODULE_NAME := kvx

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m := $(MODULE_NAME).o

$(MODULE_NAME)-y := \
	src/module.o \
	src/vm.o \
	src/vmx.o \
	src/vmx_asm.o \
	src/ept.o 

# Use ccflags-y to add the include directory to the search path
# We use $(src) which is a Kbuild variable pointing to your module source root
ccflags-y := -I$(src)/include -I$(src)/utils

.PHONY: all clean modules install unload reload

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
# ... rest of your file
