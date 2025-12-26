

MODULE_NAME := kvx

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m := $(MODULE_NAME).o

$(MODULE_NAME)-y := \
	src/module.o \
	src/vm.o \
	src/vmx.o

$(MODULE_NAME)-y += src/vmx_asm.o

ccflags-y := \
	-I$(PWD)/include \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-Wno-missing-field-initializers \
	-fno-omit-frame-pointer


.PHONY: all clean modules install unload reload

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: modules
	sudo insmod $(MODULE_NAME).ko

unload:
	sudo rmmod $(MODULE_NAME)

reload: unload install
