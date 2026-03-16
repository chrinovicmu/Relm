#ifndef RELM_APIC_H
#define RELM_APIC_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/ktime.h> 
#include <stdint.h>

struct vcpu; 
struct relm_vm; 

#define APIC_DEFAULT_BASE           0xFEE00000ULL
#define APIC_REGISTER_SIZE          0x1000ULL   /* 4 KB APIC register page */
 
/*APIC REGISTER OFFSETS*/ 
#define APIC_REG_ID                 0x020
#define APIC_REG_VERSION            0x030
#define APIC_REG_TPR                0x080   /* Task Priority Register — fast path */
#define APIC_REG_APR                0x090
#define APIC_REG_PPR                0x0A0
#define APIC_REG_EOI                0x0B0   /* Write-only, side-effectin*/
#define APIC_REG_RRD                0x0C0
#define APIC_REG_LDR                0x0D0
#define APIC_REG_DFR                0x0E0
#define APIC_REG_SVR                0x0F0   /* APIC SW enable bit 8               */
#define APIC_REG_ISR(n)             (0x100 + (n) * 0x10)   /* n = 0..7 */
#define APIC_REG_TMR(n)             (0x180 + (n) * 0x10)
#define APIC_REG_IRR(n)             (0x200 + (n) * 0x10)
#define APIC_REG_ESR                0x280
#define APIC_REG_LVT_CMCI           0x2F0
#define APIC_REG_ICR_LOW            0x300   /* Write triggers IPI                 */
#define APIC_REG_ICR_HIGH           0x310
#define APIC_REG_LVT_TIMER          0x320
#define APIC_REG_LVT_THERMAL        0x330
#define APIC_REG_LVT_PMC            0x340
#define APIC_REG_LVT_LINT0          0x350
#define APIC_REG_LVT_LINT1          0x360
#define APIC_REG_LVT_ERROR          0x370
#define APIC_REG_TIMER_ICR          0x380
#define APIC_REG_TIMER_CCR          0x390   /* Read-only, derived from time       */
#define APIC_REG_TIMER_DCR          0x3E0

#define VMCS_VIRTUAL_APIC_PAGE_ADDR     0x2012
#define VMCS_APIC_ACCESS_ADDR           0x2014
#define VMCS_TPR_THRESHOLD              0x401C

#ifndef VMCS_PROC2_VIRTUALIZE_APIC_ACCESSES
#define VMCS_PROC2_VIRTUALIZE_APIC_ACCESSES    (1U << 0)
#endif

#ifndef VMCS_PROC2_APIC_REGISTER_VIRT
#define VMCS_PROC2_APIC_REGISTER_VIRT          (1U << 8)
#endif 

#define EXIT_REASON_APIC_ACCESS         44 
#define APIC_ACCESS_OFFSET_MASK         0x00000FFFU  /* bits 11:0 = reg offset */
#define APIC_ACCESS_TYPE_MASK           0x0000F000U  /* bits 15:12 = access type */
#define APIC_ACCESS_TYPE_SHIFT          12
 
#define APIC_ACCESS_TYPE_LINEAR_READ    0   /* read  during instruction exec  */
#define APIC_ACCESS_TYPE_LINEAR_WRITE   1   /* write during instruction exec  */
#define APIC_ACCESS_TYPE_LINEAR_FETCH   2   /* instruction fetch (rare)       */
#define APIC_ACCESS_TYPE_EVENT_DELIVERY 3   /* during IDT vectoring           */
#define APIC_ACCESS_TYPE_PHYS_READ      10  /* physical (paging disabled)     */
#define APIC_ACCESS_TYPE_PHYS_EVENT     15  /* physical during event delivery */

/*APIC VERSION and SVR constants*/ 

#define APIC_VERSION_VALUE              0x00050014U /*intergated APIC, maxlvt=5*/ 
#define APIC_SVR_RESET_VALUE            0X000000FFU /*APIC disabled*/ 
#define APIC_SVR_SW_ENALE               (1U << 8)
#define APIC_LVT_MASKED                 (1ULL << 16)
#define APIC_LVT_RESET_VALUE            APIC_LVT_MASKED

/* ICR fields */
#define APIC_ICR_VECTOR_MASK            0x000000FFU
#define APIC_ICR_DELIVERY_MASK          0x00000700U
#define APIC_ICR_DELIVERY_SHIFT         8
#define APIC_ICR_DELIVERY_FIXED         (0U << 8)
#define APIC_ICR_DELIVERY_NMI           (4U << 8)
#define APIC_ICR_DELIVERY_INIT          (5U << 8)
#define APIC_ICR_DELIVERY_STARTUP       (6U << 8)
#define APIC_ICR_SEND_PENDING           (1U << 12)
#define APIC_ICR_TRIGGER_LEVEL          (1U << 15)
#define APIC_ICR_SHORTHAND_MASK         0x000C0000U
#define APIC_ICR_SHORTHAND_NONE         0x00000000U
#define APIC_ICR_SHORTHAND_SELF         0x00040000U
#define APIC_ICR_DEST_SHIFT             24

/* 256-bit bitmap helpers: each bitmap is uint32_t[8], bit N = vector N */
#define APIC_VEC_WORD(v)        ((v) >> 5)
#define APIC_VEC_BIT(v)         ((v) & 0x1F)
#define APIC_VEC_MASK(v)        (1U << APIC_VEC_BIT(v))

/* DCR values */
#define APIC_TIMER_DCR_DIV1     0x0BU
#define APIC_TIMER_DCR_DIV2     0x00U
#define APIC_TIMER_DCR_DIV4     0x01U
#define APIC_TIMER_DCR_DIV16    0x03U

enum virt_apic_timer_mode {
    APIC_TIMER_MODE_ONESHOT      = 0,
    APIC_TIMER_MODE_PERIODIC     = 1,
    APIC_TIMER_MODE_TSC_DEADLINE = 2,
};

struct virt_apic{

    uint8_t *vapic_page; 
    uint64_t vapic_page_pa; 

    uint8_t *apic_access_page; 
    uint64_t apic_access_page_pa; 

    uint32_t apic_id; 
    uint32_t version; 
    uint32_t tpr; 
    uint32_t ppr; 
    uint32_t svr; 
    uint32_t ldr; 
    uint32_t dfr; 
    uint32_t esr; 
    uint32_t irr[8]; 
    uint32_t isr[8]; 
    uint32_t tmr[8]; 
    uint32_t isr_low; 
    uint32_t isr_high; 
    uint32_t lvt_timer; 
    uint32_t lvt_thermal; 
    uint32_t lvt_pmc; 
    uint32_t lvt_lint0; 
    uint32_t lvt_lint1; 
    uint32_t lvt_error; 
    uint32_t timer_icr; 
    uint32_t timer_dcr; 

    enum virt_apic_timer_mode; 
    uint64_t timer_start_ns; 
    uint64_t timer_deadline_tsc; 

    bool is_enabled; 
    bool apic_reg_virt_supported; 
    
    spinlock_t lock; 
}; 

int relm_apic_alloc(struct virt_apic *apic);
void relm_apic_free(struct virt_apic *apic);
void relm_apic_init(struct virt_apic *apic, uint8_t apic_id);
int relm_apic_vmcs_setup(struct vcpu *vcpu);
int relm_apic_ept_setup(struct vcpu *vcpu);

/*handle EXIT_REASON_APIC_ACCESS (exit 14)*/ 
int relm_handle_apic_handle_access(struct vcpu *vcpu); 

/*emulate guest write/read*/  
int relm_apic_read(struct vcpu *vcpu, uint32_t offset, uint32_t *value); 
int relm_apic_write(struct vcpu *vcpu, uint32_t offset, uint32_t value); 

void relm_apic_ppr_update(struct virt_apic *apic); 

/*set bit vector in IRR */ 
void relm_apic_inject_interrupt(struct virt_apic *apic, uint8_t vector, 
                                bool level_triggered); 

/*write vlaue to both the sofware struct and the virtual-apic page at the offset*/ 
static inline void relm_vapic_sync_reg(struct virt_apic *apic,
                                       uint32_t offset, uint32_t value); 
{
    if(apic->vapic_page && offset < APIC_REGISTER_SIZE)
        *((volatile uint32_t *)(apic->vapic+page + offset)) = value; 
}

static inline uint32_t relm_vapic_read_reg(struct virt_apic *apic,
                                           uint32_t offset)
{
    if(apic->vapic_page && offset < APIC_REGISTER_SIZE)
        return *((volatile uint32_t *)(apic->vapic_page + offset)); 
    return 0; 
}
uint32_t relml_apic_get_timer_ccr(struct virt_apic *apic); 

#endif 
