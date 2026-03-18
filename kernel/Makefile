
# Tell kbuild to build relm.ko from these object files
obj-m := relm.o

relm-objs := \
    module.o        \
    vm.o            \
    vmx.o           \
    vmexit.o        \
    vmx.o           \
    guest_kernel_embed.o

# Tools — use the kernel build system's cross-compile aware versions
AS      := $(CROSS_COMPILE)as
OBJCOPY := $(CROSS_COMPILE)objcopy

# Source directory (where this Makefile and all .s/.S files live)
src_dir := $(shell pwd)

# -----------------------------------------------------------------------
# Step 1: Assemble guest_kernel.s → guest_kernel.bin
#
# We produce guest_kernel.bin in two sub-steps because GNU as cannot
# directly emit a flat binary — it always produces an ELF object.
# objcopy --output-target binary strips all ELF headers and emits only
# the raw bytes of the .text section, which is exactly what we need.
#
# The binary is placed in the module source directory so that .incbin
# in guest_kernel_embed.S can find it with a plain relative path.
# -----------------------------------------------------------------------
$(src_dir)/guest_kernel.o: $(src_dir)/guest_kernel.s
	@echo "  AS      guest_kernel.s"
	$(AS) --64 -o $@ $<

$(src_dir)/guest_kernel.bin: $(src_dir)/guest_kernel.o
	@echo "  OBJCOPY guest_kernel.o -> guest_kernel.bin"
	$(OBJCOPY) --output-target binary $< $@
	@echo "  GUEST   $(shell wc -c < $@) bytes"

# -----------------------------------------------------------------------
# Step 2: guest_kernel_embed.o depends on guest_kernel.bin
#
# kbuild would normally compile guest_kernel_embed.S without checking
# whether guest_kernel.bin exists first. This explicit rule adds the
# dependency so make serialises the steps correctly.
# -----------------------------------------------------------------------
$(obj)/guest_kernel_embed.o: $(src_dir)/guest_kernel.bin

# -----------------------------------------------------------------------
# Clean rule — remove generated files alongside the standard kbuild output
# -----------------------------------------------------------------------
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build \
	        M=$(src_dir) clean
	rm -f $(src_dir)/guest_kernel.o \
	      $(src_dir)/guest_kernel.bin

.PHONY: clean
