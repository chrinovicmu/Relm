
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/msr.h>
#include <asm/processor.h>   // __read_cr4 / __write_cr4

#define IA32_FEATURE_CONTROL 0x3A
#define FEAT_CTL_LOCK        (1ULL << 0)
#define FEAT_CTL_VMXON_SM    (1ULL << 2)

static int __init vmx_probe_init(void)
{
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    u64 feat_ctl;
    unsigned long cr4;

    pr_info("VMX_PROBE: init\n");

    native_cpuid(&eax, &ebx, &ecx, &edx);

    if (!(ecx & (1 << 5))) {
        pr_err("VMX_PROBE: VMX NOT supported by CPU\n");
        return -ENODEV;
    }

    pr_info("VMX_PROBE: VMX supported by CPU\n");

    rdmsrl(IA32_FEATURE_CONTROL, feat_ctl);
    pr_info("VMX_PROBE: IA32_FEATURE_CONTROL = 0x%llx\n", feat_ctl);

    if (!(feat_ctl & FEAT_CTL_LOCK)) {
        pr_alert("VMX_PROBE: FEATURE_CONTROL NOT LOCKED\n");
    } else {
        if (!(feat_ctl & FEAT_CTL_VMXON_SM)) {
            pr_err("VMX_PROBE: VMXON disabled outside SMX by BIOS\n");
            return -EPERM;
        }
        pr_info("VMX_PROBE: VMXON allowed outside SMX\n");
    }

    cr4 = __read_cr4();
    pr_info("VMX_PROBE: CR4 before = 0x%lx\n", cr4);

    __write_cr4(cr4 | X86_CR4_VMXE);

    cr4 = __read_cr4();
    pr_info("VMX_PROBE: CR4 after  = 0x%lx\n", cr4);

    pr_info("VMX_PROBE: VMXE enabled safely (no VMXON)\n");
    return 0;
}

static void __exit vmx_probe_exit(void)
{
    unsigned long cr4;

    cr4 = __read_cr4();
    __write_cr4(cr4 & ~X86_CR4_VMXE);

    pr_info("VMX_PROBE: VMXE cleared\n");
}

module_init(vmx_probe_init);
module_exit(vmx_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chrinovic");
MODULE_DESCRIPTION("Minimal VMX support + CR4.VMXE probe");
