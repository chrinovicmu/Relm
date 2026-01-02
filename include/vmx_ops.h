#ifndef VMX_OPS_H 
#define VMX_OPS_H

#include "vmcs_state.h"
#include "vmcs.h"

asmlinkage void ex_handler_rdmsr_unsafe(void); 
asmlinkage void ex_handler_rdmsr_unsafe(void)
{

}
static inline void cpuid(uint32_t leaf,
                         uint32_t *eax,
                         uint32_t *ebx,
                         uint32_t *ecx,
                         uint32_t *edx)
{
    asm volatile("cpuid"
        : "=a"(*eax), "=b"(*ebx),
        "=c"(*ecx), "=d"(*edx)
        : "a"(leaf));
}

static inline unsigned long long notrace __rdmsr1(unsigned int msr)
{
    /* low = eax = 0-31 
     * high = edx = 32-63 */  

    unsigned int high;  
    unsigned int low; 

    __asm__ __volatile__ (
        "1: rdmsr\n"
        "2:\n"
        /*switch to exception table temporarily */ 
        ".pushsection __ex_table, \"a\"\n"
        ".balign 8\n"
        ".long (1b - .), (2b - .), ex_handler_rdmsr_unsafe - .\n"
        ".popsection\n"

        : "=a" (low), "=d" (high) 
        : "c" (msr)
        : "memory"
    ); 

    return ((unsigned long long)high << 32) | low; 
}

bool cpu_has_vpid(void)
{
    uint32_t eax, ebx, ecx, edx;

    /* CPUID leaf 1: ECX[5] == VPID */
    cpuid(1, &eax, &ebx, &ecx, &edx);

    return (ecx & (1u << 5)) != 0;
}

static inline uint64_t _read_cr0(void)
{
    uint64_t val;

    __asm__ __volatile__ (
        "mov %%cr0, %0" 
        : "=r"(val)
    );

    return val;
}

static inline uint64_t _read_cr2(void)
{
    uint64_t val;

    __asm__ __volatile__ (
        "mov %%cr2, %0" 
        : "=r"(val)
    );

    return val;
}

static inline uint64_t _read_cr3(void) 
{
    uint64_t val;

    __asm__ __volatile__ (
        "mov %%cr3, %0" 
        :"=r"(val)
    );

    return val;
}

static inline uint64_t _read_cr4(void) 
{
    uint64_t val;

    __asm__ __volatile__ ("mov %%cr4, %0" 
        : "=r"(val)
    );

    return val;
}


/*get revision id*/ 

static inline uint32_t _vmcs_revision_id(void)
{
    return __rdmsr1(MSR_IA32_VMX_BASIC); 
}

static inline uint8_t _vmxon(uint64_t vmxon_phys_addr)
{
    uint8_t ret; 
    
    __asm__ __volatile__ (
        "vmxon %[pa]; setna %[ret]"
        :[ret] "=rm"(ret)
        :[pa]  "m"  (vmxon_phys_addr)
        :"cc", "memory"
    );

    return ret; 
}

static inline int _vmptrld(uint64_t vmcs_phys_addr)
{
    uint8_t ret; 

    __asm__ __volatile__ (
        "vmptrld %[pa]; setna %[ret]"
        :[ret] "=rm"(ret)
        :[pa]  "m"  (vmcs_phys_addr)
        : "cc", "memory"
    ); 
    return ret; 
}

static inline int _vmread_safe(uint64_t field_enc, uint64_t *value)
{
    uint8_t ret; 
    uint64_t val; 

    __asm__ __volatile__ (
        "vmread %[field_enc], %[val]; setna %[ret]"
        :[ret] "=rm"(ret), [val] "=r"(val)
        :[field_enc] "r" (field_enc)
        :"cc"
    ); 
     
    *value = val;

    return ret ? 1 : 0;
}

static inline unsigned long __vmread(uint64_t field_enc)
{
    uint64_t val; 
    return _vmread_safe(field_enc, &val) ? 0 : val; 
}
static inline int _vmwrite(uint64_t field_enc, uint64_t value)
{
    uint8_t status; 

    __asm__ __volatile__ (
        "vmwrite %[value], %[field_enc]; setna %[status]"
        :[status] "=rm" (status)
        :[value] "rm"(value), [field_enc] "r" (field_enc)
        :"cc"
    ); 

    if(!status)
    {
        return 0; 
    }

    /*pushes error code to error field of vmcs on write fails */ 

    else
    {
        uint64_t error_code = __vmread(VMCS_INSTRUCTION_ERROR_FIELD); 

        if(error_code == 0)
        {
            return (int)error_code; 
        } 
        else
        {
            return - 1; 

        }

    }
}
static inline int __vmclear(u64 pa)
{
    u8 error;
    asm volatile (
        "vmclear %1; "
        "setna %0"      /* Set 'error' if CF=1 or ZF=1 */
        : "=q" (error)
        : "m" (pa)
        : "cc", "memory"
    );

    return error;
}
static inline int _vmlaunch(void)
{
    int ret;

    __asm__ __volatile__ (
        "push %%rbp;"
        "push %%rcx;"
        "push %%rdx;"
        "push %%rsi;"
        "push %%rdi;"
        "push $0;"
        "vmwrite %%rsp, %[host_rsp];"
        "lea 1f(%%rip), %%rax;"
        "vmwrite %%rax, %[host_rip];"
        "vmlaunch;"
        "incq (%%rsp);"
        "1: pop %%rax;"
        "pop %%rdi;"
        "pop %%rsi;"
        "pop %%rdx;"
        "pop %%rcx;"
        "pop %%rbp;"
        : [ret] "=&a"(ret)
        : [host_rsp] "r"((uint64_t)HOST_RSP),
        [host_rip] "r"((uint64_t)HOST_RIP)
        : "memory", "cc", "rbx", "r8", "r9", "r10", 
        "r11", "r12", "r14", "r15"
    );

    return ret; 
}

static inline int _get_vmcs_size(void)
{
    uint64_t vmx_basic = __rdmsr1(MSR_IA32_VMX_BASIC); 
    uint32_t vmcs_size = (vmx_basic > 32) & 0x1FFF; 

    if(!vmcs_size)
    {
        pr_err("Invalid VMCS size from VMX_BASIC MSR: 0x%ll\n", vmx_basic); 
        return -1; 

    }

    pr_err("VMX_BASIC MSR: 0x%llx, VMCS size: %u bytes\n", vmx_basic, vmcs_size);
    return vmcs_size;
}

#endif 
