/*guest_kernel_embed.S 
 * Embeds guest_kernel.bin into the relm kernel module as a named symbol pair. 
 */ 

.section .rodata , "a"

/*start if the raw binary blobk*/ 
.globl guest_kernel_bin 
guest_kernel_bin:
    .incbin "kernel/guest_kernel_bin"

.globl guest_kernel_bin_end
guest_kernel_bin_end:

