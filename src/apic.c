#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/smp.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
 
#include <include/vmx.h>
#include <include/vm.h>
#include <include/vmx_ops.h>
#include <include/vmexit.h>
#include <include/apic.h>
#include <include/ept.h>
#include <utils/utils.h>

/*EPT permissons flags for the APIC-access page at GPA 0xFEE00000. 
* R=1 W=1 X=0, MemTYpe = UC */ 
#define EPT_APIC_FLAGS (0x3ULL)


int relm_apic_alloc(struct virt_apic *apic)
{
    apic->vapic_page = (uint8_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if(!apic->vapic_page)
    {
        pr_err("RELM: APIC: failed to allocate virtual-APIC page\n");
        return -ENOMEM;
    }
    apic->vapic_page_pa = virt_to_phys(apic->vapic_page);
 
    apic->apic_access_page = (uint8_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if(!apic->apic_access_page)
    {
        pr_err("RELM: APIC: failed to allocate APIC-access page\n");
        free_page((unsigned long)apic->vapic_page);
        apic->vapic_page    = NULL;
        apic->vapic_page_pa = 0;
        return -ENOMEM;
    }
    apic->apic_access_page_pa = virt_to_phys(apic->apic_access_page);
 
    pr_info("RELM: APIC: allocated vapic_page PA=0x%llx, "
            "apic_access_page PA=0x%llx\n",
            apic->vapic_page_pa, apic->apic_access_page_pa);
    return 0;
}
 
void relm_apic_free(struct virt_apic *apic)
{
    if(apic->vapic_page)
    {
        free_page((unsigned long)apic->vapic_page);
        apic->vapic_page    = NULL;
        apic->vapic_page_pa = 0;
    }
    if(apic->apic_access_page)
    {
        free_page((unsigned long)apic->apic_access_page);
        apic->apic_access_page    = NULL;
        apic->apic_access_page_pa = 0;
    }
}

void relm_apic_init(struct virt_apic *apic, uint8_t apic_id)
{
    int i; 

    spin_lock_init(&apic->lock); 

    apic->apic_id = (uint32_t)apic_id << 24; 
    apic->version = APIC_VERSION_VALUE; 

    apic->svr = APIC_SVR_RESET_VALUE;

    /*DFR= flat logical address mode */ 
    apic->dfr = 0xFFFFFFFFU; 

    /*all LVT entries start masked */ 
    apic->lvt_timer   = APIC_LVT_RESET_VALUE;
    apic->lvt_thermal = APIC_LVT_RESET_VALUE;
    apic->lvt_pmc     = APIC_LVT_RESET_VALUE;
    apic->lvt_lint0   = APIC_LVT_RESET_VALUE;
    apic->lvt_lint1   = APIC_LVT_RESET_VALUE;
    apic->lvt_error   = APIC_LVT_RESET_VALUE;

    for(i = 0; i < 8; i++)
        apic->irr[i] = apic->isr[i] = apic->tmr[i] = 0;
 
    apic->tpr = apic->ppr = apic->esr = apic->ldr = 0;
    apic->icr_low = apic->icr_high = 0;
    apic->timer_icr = apic->timer_dcr = 0;
    apic->timer_mode = APIC_TIMER_MODE_ONESHOT;
    apic->timer_start_ns = apic->timer_deadline_tsc = 0;
    apic->is_enabled = false;
    apic->timer_dcr  = APIC_TIMER_DCR_DIV1;

    /*populate the virtual-APIC page with the same reset values */ 
    if(apic->vapic_page)
    {
        relm_vapic_sync_reg(apic, APIC_REG_ID,          apic->apic_id);
        relm_vapic_sync_reg(apic, APIC_REG_VERSION,     apic->version);
        relm_vapic_sync_reg(apic, APIC_REG_TPR,         apic->tpr);
        relm_vapic_sync_reg(apic, APIC_REG_PPR,         apic->ppr);
        relm_vapic_sync_reg(apic, APIC_REG_LDR,         apic->ldr);
        relm_vapic_sync_reg(apic, APIC_REG_DFR,         apic->dfr);
        relm_vapic_sync_reg(apic, APIC_REG_SVR,         apic->svr);
        relm_vapic_sync_reg(apic, APIC_REG_ESR,         apic->esr);
        relm_vapic_sync_reg(apic, APIC_REG_ICR_HIGH,    apic->icr_high);
        relm_vapic_sync_reg(apic, APIC_REG_LVT_TIMER,   apic->lvt_timer);
        relm_vapic_sync_reg(apic, APIC_REG_LVT_THERMAL, apic->lvt_thermal);
        relm_vapic_sync_reg(apic, APIC_REG_LVT_PMC,     apic->lvt_pmc);
        relm_vapic_sync_reg(apic, APIC_REG_LVT_LINT0,   apic->lvt_lint0);
        relm_vapic_sync_reg(apic, APIC_REG_LVT_LINT1,   apic->lvt_lint1);
        relm_vapic_sync_reg(apic, APIC_REG_LVT_ERROR,   apic->lvt_error);
        relm_vapic_sync_reg(apic, APIC_REG_TIMER_ICR,   apic->timer_icr);
        relm_vapic_sync_reg(apic, APIC_REG_TIMER_DCR,   apic->timer_dcr);
        
        for(i = 0; i < 8; i++)
        {
            relm_vapic_sync_reg(apic, APIC_REG_ISR(i), 0);
            relm_vapic_sync_reg(apic, APIC_REG_TMR(i), 0);
            relm_vapic_sync_reg(apic, APIC_REG_IRR(i), 0);
        }
    }

    pr_info("RELM: APIC%u: initialised (vapic_pa=0x%llx "
            "access_pa=0x%llx)\n",
            apic_id, apic->vapic_page_pa, apic->apic_access_page_pa);
}

int relm_apic_vmcs_setup(struct vcpu *vcpu)
{
    struct virt_apic *apic = &vcpu->apic; 
    uint64_t msr; 
    uint32_t allowed1; 
    bool apic_reg_virt_ok; 

    if(!apic->vapic_page_pa || !apic->apic_access_page_pa)
    {
        pr_err("RELM: APIC: VMCS setup called before page allocation\n");
        return -EINVAL;
    }

    if(_vmwrite(VMCS_VIRTUAL_APIC_PAGE_ADDR, apic->vapic_page_pa) != 0)
    {
        pr_err("RELM: APIC: failed to write VIRTUAL_APIC_PAGE_ADDR\n");
        return -EIO;
    }

    PDEBUG("RELM: APIC: VIRTUAL_APIC_PAGE_ADDR = 0x%llx\n",
           apic->vapic_page_pa);

    if(_vmwrite(VMCS_APIC_ACCESS_ADDR, apic->apic_access_page_pa) != 0)
    {
        pr_err("RELM: APIC: failed to write APIC_ACCESS_ADDR\n");
        return -EIO;
    }

    PDEBUG("RELM: APIC: APIC_ACCESS_ADDR = 0x%llx\n",
           apic->apic_access_page_pa);

    /* i set threshold = 0. since TPR class is always >= 0, this condition
     * is never true, and exit 43 never fires. TPR changes are completely
     * transparent — the guest raises/lowers TPR with zero VM-exits. */ 

    if(_vmwrite(VMCS_TPR_THRESHOLD, 0) != 0)
    {
        pr_err("RELM: APIC: failed to write TPR_THRESHOLD\n");
        return -EIO;
    }
    PDEBUG("RELM: APIC: TPR_THRESHOLD = 0 (threshold exits disabled)\n");

    /*check if secondary controls allow enabling VIRTUALIZE_APIC_ACCESSES */
    msr      = __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS2);
    allowed1 = (uint32_t)(msr >> 32);
 
    if(!(allowed1 & VMCS_PROC2_VIRTUALIZE_APIC_ACCESSES))
    {
        pr_warn("RELM: APIC: CPU does not support VIRTUALIZE_APIC_ACCESSES "
                "— falling back to EPT-violation interception\n");
        apic->apic_reg_virt_supported = false;
        return 0;
    }

    uint32_t current_sec = (uint32_t)__vmread(
                            VMCS_SECONDARY_PROC_BASED_EXEC_CONTROLS);
    uint32_t new_sec = current_sec | VMCS_PROC2_VIRTUALIZE_APIC_ACCESSES;
 
    /*enable APIC-register virtualisation (bit 8) for zero-exit reads */
    apic_reg_virt_ok = (allowed1 & VMCS_PROC2_APIC_REGISTER_VIRT) != 0;
    if(apic_reg_virt_ok)
    {
        new_sec |= VMCS_PROC2_APIC_REGISTER_VIRT;
        pr_info("RELM: APIC: APIC-register virtualisation supported and enabled "
                "(reads from vapic_page, zero VM-exits)\n");
    }
    else
    {
        pr_info("RELM: APIC: APIC-register virtualisation NOT supported "
                "(reads will still cause exit 44)\n");
    }
 
    if(_vmwrite(VMCS_SECONDARY_PROC_BASED_EXEC_CONTROLS, new_sec) != 0)
    {
        pr_err("RELM: APIC: failed to re-write secondary proc controls\n");
        return -EIO;
    }
 
    apic->apic_reg_virt_supported = apic_reg_virt_ok;
 
    pr_info("RELM: APIC: VMCS setup complete — "
            "VIRTUALIZE_APIC_ACCESSES=1 APIC_REGISTER_VIRT=%d "
            "TPR_THRESHOLD=0\n",
            apic_reg_virt_ok ? 1 : 0);
    return 0;
}

int relm_apic_ept_setup(struct vcpu *vcpu)
{
    struct virt_apic *apic = &vcpu->apic; 
    struct relm_vm *vm = vcpu->vm; 
    int ret; 

    if(!vm || !vm->ept)
    {
        pr_err("RELM: APIC EPT: no EPT context\n");
        return -EINVAL;
    }
 
    if(!apic->apic_access_page_pa)
    {
        pr_err("RELM: APIC EPT: apic_access_page not allocated\n");
        return -EINVAL;
    }

    ret = relm_ept_map_page(vm->ept,
                            APIC_DEFAULT_BASE, 
                            apic->apic_access_page_pa,
                            EPT_APIC_FLAGS); 
    if(ret < 0)
    {
        pr_err("RELM: APIC EPT: failed to map GPA 0x%llx → HPA 0x%llx: %d\n",
               APIC_DEFAULT_BASE, apic->apic_access_page_pa, ret);
        return ret;
    }
 
    pr_info("RELM: APIC EPT: mapped GPA 0x%llx → HPA 0x%llx "
            "(APIC-access page, R=1 W=1 X=0 UC)\n",
            APIC_DEFAULT_BASE, apic->apic_access_page_pa);
    return 0;

}

void relm_apic_set_error(struct virt_apic *apic, uint32_t error_bit)
{
    error_bit &= APIC_ESR_VALID_BITS; 
    if(!error_bit)
        return; 

    apic->esr_pending |= error_bit; 
 
    PDEBUG("RELM: APIC: ESR error recorded: bit=%u esr_pending=0x%02x",
           __builtin_ctz(error_bit),   /* ctz = count trailing zeros = bit position */
           apic->esr_pending & APIC_ESR_VALID_BITS);


    if(apic->is_enabled && !(apic->lvt_error & APIC_LVT_MASKED))
    {
        uint8_t error_vector = (uint8_t)(apic->lvt_error & APIC_LVT_VECTOR_MASK);

        /*validate the error vectro before injecting 
         * if guest programmed a vector < 16 into LVT_ERROR, injectign it would 
         * itself be an illegal-vector error */ 
        if(error_vector >= APIC_ILLEGAL_VECTOR_THRESHOLD)
        {
            PDEBUG("RELM: APIC: injecting LVT Error interrupt vector=0x%02x",
                   error_vector);

            relm_apic_inject_interrupt(apic, error_vector, false); 
        }
        else {
           PDEBUG("RELM: APIC: LVT_ERROR has illegal vector=0x%02x "
                   "— error interrupt not injected",error_vector);
        }

    }
}

/*PPR update */ 
void relm_apic_ppr_update(struct virt_apic *apic)
{
    uint32_t isrv = 0; 
    uint32_t tpr_class; 
    int word, bit; 

    for(word = 7; word >= 0; word--)
    {
        if(apic->isr[word] != 0)
        {
            bit = 31 - __builtin_clz(apic->isr[word]); 
            isrv = (uint32_t)((word * 32) + bit); 
            break; 
        }
    }
    tpr_class = apic->tpr & 0xF0U; 

    if(isrv > 0)
    {
        uint32_t isr_class = isrv & 0xF0U; 
        apic->ppr = (isr_class > tpr_class) ? isr_class : tpr_class; 
    }
    else{
        apic->ppr = tpr_class; 
    }

    relm_vapic_sync_reg(apic, APIC_REG_PPR, apic->ppr); 
}

/*EOI 
* clears the highest proiority ISR bit 
* writing to the EOI register (offset 0xB0) signals that the CPU 
* finished servicing the highest-priority in-service interrupt*/ 

static void relm_apic_eoi(struct virt_apic *apic)
{
    int word, bit; 
    uint8_t vector = 0; 
    bool found = false; 
    
    /*find highest proiority isr entry */ 
    for(word = 7; word >= 0 && !found; word--)
    {
        if(apic->isr[word] != 0)
        {
            bit = 31 - __builtin_clz(apic->isr[word]); 
            vector = (uint8_t)((word * 32) + bit); 
            apic->isr[word] &= ~(1U << bit); 
            relm_vapic_sync_reg(apic, APIC_REG_ISR(word), apic->isr[word]); 
            found = true; 
        }
    }

    if(!found)
    {
        PDEBUG("RELM: APIC: spurios EOI(ISR empty)\n"); 
        return; 
    }

    if(apic->tmr[APIC_VEC_WORD(vector)] & APIC_VEC_MASK(vector))
    {
        apic->tmr[APIC_VEC_WORD(vector)] &= ~APIC_VEC_MASK(vector);
        relm_vapic_sync_reg(apic, APIC_REG_TMR(APIC_VEC_WORD(vector)),
                            apic->tmr[APIC_VEC_WORD(vector)]);
        PDEBUG("RELM: APIC: EOI level-triggered vector %u\n", vector);
    }
    else
    {
        PDEBUG("RELM: APIC: EOI edge-triggered vector %u\n", vector);
    }
 
    relm_apic_ppr_update(apic);
}

static int relm_apic_ipi_resolve_targets(struct relm_vm *vm, 
                                         struct vcpu *sender, 
                                         uint32_t icr_low, 
                                         uint32_t icr_high, 
                                         struct vcpu **targets, 
                                         int max_targets)
{
    uint32_t shorthand = icr_low & APIC_ICR_SHORTHAND_MASK; 
    bool logical = (icr_low & (1U << 11)) != 0; /*des mode*/ 
    uint8_t dest_field = (uint8_t)(icr_high >> APIC_ICR_DEST_SHIFT); 
    int found = 0; 
    int i; 

    if(!vm || !vm->vcpus)
        return 0; 

    for(i = 0; i < vm->max_vcpus && found < max_targets; i++)
    {
        struct vcpu *candidate = vm->vcpus[i];

        /*skip empty slots*/ 
        if(!candidate)
            continue;

        switch(shorthand)
        {
            case APIC_ICR_SHORTHAND_SELF:
                /*Deliver only to CPU that wrote ICR_LOW*/ 
                if(candidate == sender)
                    targets[found++] = candidate; 
                break; 

            case APIC_ICR_SHORTHAND_ALL_INCL:
                /*broadcast to all vcpus including sender.*/ 
                targets[found++] = candidate; 
                break;

            case APIC_ICR_SHORTHAND_ALL_EXCL:
                /*broadcast to all vcpus expect sender */ 
                if(candidate != sender)
                    targets[found++] = candidate; 
                break; 

            case APIC_ICR_SHORTHAND_NONE:
            default:

                if(!logical)
                {
                    uint8_t cand_id = (uint8_t)(candidate->apic.apic_id >> 24); 
                    if(cand_id == dest_field)
                        targets[found++] = candidate; 
                }
                else {
                    uint8_t cand_ldr = (uint8_t)(candidate->apic.ldr >> 24); 
                    if((cand_ldr & dest_field) != 0)
                        targets[found++] = candidate; 
                }
                break; 
        }
    }

    return found; 
}

/*deliver one IPI to one resolved target VCPU */ 
static void relm_apic_ipi_deliver(struct vcpu *sender, 
                                  struct vcpu *target, 
                                  uint32_t  delivery_mode, 
                                  uint32_t vector, 
                                  bool level)
{
    switch(delivery_mode)
    {
        /*FIXED DELIVERY
         * injects the interrupt vector into target vcpu's IRR.*/

        case APIC_ICR_DELIVERY_FIXED:
            PDEBUG("RELM: APIC: IPI FIXED vec=0x%02x %s → VCPU%u",
                   vector, level ? "level" : "edge", target->vpid);

            relm_apic_inject_interrupt(&target->apic, (uint8_t)vector, level); 
            break;

        /*TODO :
         * when RELM_MAX_VCPUS > 1 
         * 1. set target VCPU to VCPU_STATE_WAIT_FOR_SIPI
         * 2.cause target vcpu's kthred to stop executing guest code 
         * 3.spin-wait for SIPI. 
         * 4.reset all VCPU VMCE guest state fields to reset values 
         */ 
        case APIC_ICR_DELIVERY_INIT:
           pr_notice("RELM: APIC: IPI INIT → VCPU%u "
                     "(VCPU reset not yet implemented — deferred)",target->vpid);
            break;

        /*TODO:
         * sends starutup request to target processor. 
         * vector encodes startup address as physical page number. 
         * target begins exection in real mode at vector page
         *
         *when RELM_MAX_VCPUS > 1 
         * 1.verify target VCPU is in VCPU_STATE_WAIT_FOR_SIPI state
         * 2.set target vcpu->regs.rip = (vector 0xFF) << 12 
         * 3.set target vcpu->rsp = 0 (real mode)
         * 4.set VMCS GUEST_CS_SELECTOR = (vector & 0xff) << 8 (real mode)
         * 5.transition target VCPU state to VCPU_STATE_RUNNING. 
         * 6.wake up target VCPU kkthread
         */

        case APIC_ICR_DELIVERY_STARTUP:
            pr_notice("RELM: APIC: IPI SIPI → VCPU%u startup_gpa=0x%05x "
                      "(VCPU wakeup not yet implemented — deferred)",
                      target->vpid, (vector & 0xFFU) << 12);

            /* TODO: relm_vcpu_do_sipi(target, (vector & 0xFF) << 12); */
            break;

        /*TODO
         * send NMI to target processor
         * NMI is delivered via the VMCS VM-entry interrupt-information field
         *1.set pending_nmi flag in target vcpu struct 
         *2.in VPCU loop, before VMRESUME, check pending_nmi
         *3. if set: write VMCS_VM_ENTRY_INTR_FIELD with:
          (1U << 31) | (2 << 8) | 2*/ 
        case APIC_ICR_DELIVERY_NMI: 
            pr_notice("RELM: APIC: IPI NMI → VCPU%u "
                      "(NMI injection not yet implemented — deferred)",
                      target->vpid);
            /* TODO: atomic_set(&target->pending_nmi, 1); */
            break; 

        /*TODO 
         * SMI IPI 
         * RELM does not yet implement SMM. */ 
        case (2U << 8): 
            pr_notice("RELM: APIC: IPI SMI → VCPU%u "
                      "(SMM not implemented — deferred)",
                      target->vpid);
            /* TODO: relm_vcpu_do_smi(target); */
            break;

        default:
            pr_warn("RELM: APIC: IPI unrecognised delivery mode=0x%03x "
                    "vec=0x%02x → VCPU%u — IPI deferred", 
                    delivery_mode, vector, target->vpid);
            break;
    }
}

static void relm_apic_handle_icr_write(struct virt_apic *apic, uint32_t value)
{
    struct vcpu *sender = container_of(apic, struct vcpu, apic); 
    struct relm_vm *vm = sender->vm; 

    uint32_t delivery_mode = (value & APIC_ICR_DELIVERY_MASK);
    uint32_t shorthand     = value & APIC_ICR_SHORTHAND_MASK;
    uint32_t vector        = value & APIC_ICR_VECTOR_MASK;
    bool     level         = (value & APIC_ICR_TRIGGER_LEVEL) != 0;
 
    struct vcpu *targets[RELM_MAX_VCPUS]; 
    int ntargets; 
    int i; 

    apic->icr_low = value; 
    relm_vapic_sync_reg(apic, APIC_REG_ICR_LOW, value & ~APIC_ICR_SEND_PENDING); 

    PDEBUG("RELM: APIC: ICR write VCPU%u → "
           "delivery=0x%03x vec=0x%02x shorthand=0x%x dest=0x%02x %s",
           sender->vpid,
           delivery_mode, vector,
           shorthand >> 18,             
           apic->icr_high >> APIC_ICR_DEST_SHIFT, 
           level ? "level" : "edge");

    ntargets = relm_apic_ipi_resolve_targets(vm, sender, 
                                             value, apic->icr_high, 
                                             targets, RELM_MAX_VCPUS); 

    if(ntargets == 0)
    {
        PDEBUG("RELM: APIC: ICR write from VCPU%u found no target VCPUs "
               "(delivery_mode=0x%03x shorthand=0x%x dest=0x%02x) "
               "— IPI correctly not delivered",
               sender->vpid,
               delivery_mode, shorthand >> 18,
               apic->icr_high >> APIC_ICR_DEST_SHIFT);
        return;
    }

    for(i =0 ;i < ntargets; i++)
    {
        relm_apic_ipi_deliver(sender, targets[i], delivery_mode, vector, level); 
    }
 
}


uint32_t relm_apic_get_timer_ccr(struct virt_apic *apic)
{
    uint64_t elapsed_ns;
    uint64_t ticks; 
    uint32_t divisor; 
    uint32_t ccr; 

    if(apic->timer_icr == 0 || apic->timer_start_ns == 0)
        return 0; 

    elapsed_ns = ktime_get_ns() - apic->timer_start_ns; 

    switch(apic->timer_dcr & 0x0FU)
    {
        case APIC_TIMER_DCR_DIV2:  divisor = 2;   break;  /* 0x00 */
        case APIC_TIMER_DCR_DIV4:  divisor = 4;   break;  /* 0x01 */
        case 0x02:                 divisor = 8;   break;
        case APIC_TIMER_DCR_DIV16: divisor = 16;  break;  /* 0x03 */
        case 0x08:                 divisor = 32;  break;
        case 0x09:                 divisor = 64;  break;
        case 0x0A:                 divisor = 128; break;
        case APIC_TIMER_DCR_DIV1:                          /* 0x0B */
        default:                   divisor = 1;   break;
    }

    ticks = elapsed_ns / (10ULL * (uint64_t)divisor); 

    if(apic->timer_mode == APIC_TIMER_MODE_PERIODIC)
        ccr = (uint32_t)(apic->timer_icr -
              (uint32_t)(ticks % (uint64_t)apic->timer_icr));
    else
        ccr = (ticks >= (uint64_t)apic->timer_icr) ? 0 :
              (uint32_t)(apic->timer_icr - ticks);

    return ccr;
}

void relm_apic_inject_interrupt(struct virt_apic *apic, uint8_t vector, 
                                bool level_triggered)
{
    uint32_t word = APIC_VEC_WORD(vector); 
    uint32_t mask = APIC_VEC_MASK(vector); 

    spin_lock(&apic->lock); 

    apic->irr[word] |= mask; 

    if(level_triggered)
        apic->tmr[word] |= mask; 
    else 
        apic->tmr[word] &= ~mask;

    relm_vapic_sync_reg(apic, APIC_REG_IRR(word), apic->irr[word]); 
    relm_vapic_sync_reg(apic, APIC_REG_TMR(word),apic->tmr[word]); 

    spin_unlock(&apic->lock); 

    PDEBUG("RELM: APIC: injected vector %u (%s) IRR[%u]=0x%08x\n",
           vector, level_triggered ? "level" : "edge",
           word, apic->irr[word]);
}

int relm_apic_read(struct vcpu *vcpu, uint32_t offset, uint32_t *value)
{
    struct virt_apic *apic = &vcpu->apic;
    uint32_t word;  
 
    if(offset & 0x3U)
    {
        pr_warn("RELM: APIC: unaligned read at offset 0x%03x (returning 0)\n",
                offset);
        *value = 0;
        return 0;
    }
 
    switch(offset)
    {
        case APIC_REG_ID:
            *value = apic->apic_id;
            break;
 
        case APIC_REG_VERSION:
            *value = apic->version;
            break;
 
        case APIC_REG_TPR:
            apic->tpr = relm_vapic_read_reg(apic, APIC_REG_TPR);
            *value = apic->tpr;
            break;
 
        case APIC_REG_APR:
        case APIC_REG_PPR:
            relm_apic_ppr_update(apic);
            *value = apic->ppr;
            break;
 
        case APIC_REG_EOI:
            *value = 0;
            break;
 
        case APIC_REG_RRD:
            *value = 0;
            break;
 
        case APIC_REG_LDR:
            *value = apic->ldr;
            break;
 
        case APIC_REG_DFR:
            *value = apic->dfr;
            break;
 
        case APIC_REG_SVR:
            *value = apic->svr;
            break;
 
        case APIC_REG_ESR:
            /* Error Status Register (offset 0x280).
             * Bits 6:0 encode the last APIC error:
             *   bit 0 = Send Checksum Error
             *   bit 1 = Receive Checksum Error
             *   bit 2 = Send Accept Error
             *   bit 3 = Receive Accept Error
             *   bit 4 = Redirectable IPI
             *   bit 5 = Send Illegal Vector
             *   bit 6 = Receive Illegal Vector
             *   bit 7 = Illegal Register Address
             * Software must write 0 to ESR first to latch the current error,
             * then read it. Linux's lapic_dump_self_esr() reads this to
             * diagnose APIC bus transmission problems.
             * SDM Vol 3A §10.5.3 'Error Handling'. */
            *value = apic->esr;
            break;
 
        case APIC_REG_LVT_CMCI:
            *value = APIC_LVT_MASKED;
            break;
 
        case APIC_REG_ICR_LOW:
            *value = apic->icr_low & ~APIC_ICR_SEND_PENDING;
            break;
 
        case APIC_REG_ICR_HIGH:
            *value = apic->icr_high;
            break;
 
        case APIC_REG_LVT_TIMER:
            *value = apic->lvt_timer;
            break;
 
        case APIC_REG_LVT_THERMAL:
            *value = apic->lvt_thermal;
            break;
 
        case APIC_REG_LVT_PMC:
            *value = apic->lvt_pmc;
            break;
 
        case APIC_REG_LVT_LINT0:
            *value = apic->lvt_lint0;
            break;
 
        case APIC_REG_LVT_LINT1:
            *value = apic->lvt_lint1;
            break;
 
        case APIC_REG_LVT_ERROR:
            *value = apic->lvt_error;
            break;
 
        case APIC_REG_TIMER_ICR:
            *value = apic->timer_icr;
            break;
 
        case APIC_REG_TIMER_DCR:
            *value = apic->timer_dcr;
            break;
 
        case APIC_REG_TIMER_CCR:
            /* CCR is the ONLY register that cannot be statically cached in
             * the virtual-APIC page, because it changes every few microseconds.
             * We derive the current value from elapsed time, then update the
             * virtual-APIC page with this fresh value so a subsequent hardware
             * read gets a reasonably current value. The approximation is fine
             * for guest software which only uses CCR to poll for timer expiry
             * or to calibrate the timer frequency. */
            *value = relm_apic_get_timer_ccr(apic);
            relm_vapic_sync_reg(apic, APIC_REG_TIMER_CCR, *value);
            break;
 
        default:
            /* ISR, TMR, IRR: each is an 8-word 256-bit bitmap array.
             * Compute which array element to return from the offset. */
            if(offset >= APIC_REG_ISR(0) && offset <= APIC_REG_ISR(7))
            {
                word = (offset - APIC_REG_ISR(0)) / 0x10; /* 0x10 stride */
                *value = apic->isr[word];
            }
            else if(offset >= APIC_REG_TMR(0) && offset <= APIC_REG_TMR(7))
            {
                word = (offset - APIC_REG_TMR(0)) / 0x10;
                *value = apic->tmr[word];
            }
            else if(offset >= APIC_REG_IRR(0) && offset <= APIC_REG_IRR(7))
            {
                word = (offset - APIC_REG_IRR(0)) / 0x10;
                *value = apic->irr[word];
            }
            else
            {
                PDEBUG("RELM: APIC: read from reserved offset 0x%03x\n",
                       offset);
                *value = 0;
                return -EINVAL;
            }
            break;
    }
 
    PDEBUG("RELM: APIC: read offset=0x%03x → 0x%08x\n", offset, *value);
    return 0;
}

/*all APIC writes cause APIC-access VM-exits(reason 44, access type 1) 
 * */ 
int relm_apic_write(struct vcpu *vcpu, uint32_t offset, uint32_t value)
{
    struct virt_apic * apic = &vcpu->apic; 

    /*silenty ignore unaligned writes */ 
    if(offset & 0x3U)
    {
        pr_warn("RELM: APIC: unaligned write at offset 0x%03x val=0x%08x "
                "(ignored)\n", offset, value);
        return 0;
    }
 
    PDEBUG("RELM: APIC: write offset=0x%03x value=0x%08x\n", offset, value);
    
    switch(offset)
    {
        case APIC_REG_ID:
            
            /*only 31:24 are significant; lower 24 bits are reserved and must be 0 */ 
            apic->apic_id = value & 0xFF000000U; 
            relm_vapic_sync_reg(apic, APIC_REG_ID, apic->apic_id); 
            break ;

        case APIC_REG_VERSION: 
            /*version register is read-only. hardware ignores writes silenty*/ 
            break ;

        case APIC_REG_TPR:
             
             /* Only bits [7:0] are significant; bits [31:8] are reserved. */
            apic->tpr = value & 0xFFU;
            relm_vapic_sync_reg(apic, APIC_REG_TPR, apic->tpr);
            
            /* PPR depends on TPR — recompute and sync to page */
            relm_apic_ppr_update(apic);
            
            PDEBUG("RELM: APIC: TPR = 0x%02x PPR = 0x%02x\n",
                   apic->tpr, apic->ppr);
            break;

        case APIC_REG_EOI:
            /* End of Interrupt — write-only, side-effecting.
             * The written value is irrelevant (conventionally 0).
             * This triggers the multi-step EOI processing: clear ISR, update
             * TMR, potentially notify I/O APIC, recompute PPR. */
            relm_apic_eoi(apic);
            /* Write 0 to the EOI slot in the virtual-APIC page.
             * While EOI is architecturally write-only (reads are undefined),
             * zeroing it keeps the page clean */ 
            relm_vapic_sync_reg(apic, APIC_REG_EOI, 0); 
            break; 

        case APIC_REG_LDR:

            apic->ldr = value & 0xFF000000U;
            relm_vapic_sync_reg(apic, APIC_REG_LDR, apic->ldr);
            break;

        case APIC_REG_DFR:
            /* destination Format Register. Only bits [31:28] are writable;
             * bits [27:0] are reserved and read as 1. The OR with 0x0FFFFFFF
             * forces the reserved bits to 1 regardless of what the guest wrote,
             * matching real hardware behaviour per SDM §10.6.2. */
            apic->dfr = value | 0x0FFFFFFFU;
            relm_vapic_sync_reg(apic, APIC_REG_DFR, apic->dfr);
            break;

        case APIC_REG_SVR:
            
            apic->svr = value; 
            apic->is_enabled = (value & APIC_SVR_SW_ENABLE) != 0; 
            relm_vapic_sync_reg(apic, APIC_REG_SVR, apic->svr); 
            
            if(apic->is_enabled)
                pr_info("RELM: APIC: SOFTWARE ENABLED — "
                        "SVR=0x%08x spurious_vector=0x%02x\n",
                        value, value & 0xFFU);
            else
                pr_info("RELM: APIC: software disabled (SVR bit 8 cleared)\n");
            break;  

        /* ISR, TMR, IRR are READ-ONLY. Hardware ignores writes; we do too. */
        case APIC_REG_ISR(0): case APIC_REG_ISR(1): case APIC_REG_ISR(2):
        case APIC_REG_ISR(3): case APIC_REG_ISR(4): case APIC_REG_ISR(5):
        case APIC_REG_ISR(6): case APIC_REG_ISR(7):
        case APIC_REG_TMR(0): case APIC_REG_TMR(1): case APIC_REG_TMR(2):
        case APIC_REG_TMR(3): case APIC_REG_TMR(4): case APIC_REG_TMR(5):
        case APIC_REG_TMR(6): case APIC_REG_TMR(7):
        case APIC_REG_IRR(0): case APIC_REG_IRR(1): case APIC_REG_IRR(2):
        case APIC_REG_IRR(3): case APIC_REG_IRR(4): case APIC_REG_IRR(5):
        case APIC_REG_IRR(6): case APIC_REG_IRR(7):
        
            PDEBUG("RELM: APIC: write to read-only bitmap offset 0x%03x "
                   "(silently ignored)\n", offset);
            break;

        case APIC_REG_ESR:
            /* Error Status Register has unusual write semantics:
             * Software must write 0 to ESR to LATCH the current error state
             * into the readable bits, then read ESR to see the error.
             * We simply clear ESR — no real error tracking implemented yet. */
            apic->esr = apic->esr_pending & APIC_ESR_VALID_BITS; 
            apic->esr_pending = 0; 
            relm_vapic_sync_reg(apic, APIC_REG_ESR, apic->esr);

            if(apic->esr != 0)
                PDEBUG("RELM: APIC: ESR latched 0x%02x (pending cleared)\n",
                       apic->esr);
            break;

        case APIC_REG_LVT_CMCI:
            break;
        
        case APIC_REG_ICR_HIGH:
           
            apic->icr_high = value;
            relm_vapic_sync_reg(apic, APIC_REG_ICR_HIGH, value);
            break;
 
        case APIC_REG_ICR_LOW:
           
            relm_apic_handle_icr_write(apic, value);
            break;

        case APIC_REG_LVT_TIMER:
            
            apic->lvt_timer  = value;
            apic->timer_mode = (enum virt_apic_timer_mode)((value >> 17) & 0x3U);
            relm_vapic_sync_reg(apic, APIC_REG_LVT_TIMER, value);
            
            PDEBUG("RELM: APIC: LVT timer: mode=%u vector=0x%02x %s\n",
                   apic->timer_mode,
                   value & APIC_LVT_VECTOR_MASK,
                   (value & APIC_LVT_MASKED) ? "MASKED" : "unmasked");
            break;
 
        case APIC_REG_LVT_THERMAL:
           
            apic->lvt_thermal = value;
            relm_vapic_sync_reg(apic, APIC_REG_LVT_THERMAL, value);
            break;
 
        case APIC_REG_LVT_PMC:
            
            apic->lvt_pmc = value;
            relm_vapic_sync_reg(apic, APIC_REG_LVT_PMC, value);
            break;
 
        case APIC_REG_LVT_LINT0:
            
            apic->lvt_lint0 = value;
            relm_vapic_sync_reg(apic, APIC_REG_LVT_LINT0, value);
            break;

        case APIC_REG_LVT_LINT1:
          
            apic->lvt_lint1 = value;
            relm_vapic_sync_reg(apic, APIC_REG_LVT_LINT1, value);
            break;
 
        case APIC_REG_LVT_ERROR:
           
            apic->lvt_error = value;
            relm_vapic_sync_reg(apic, APIC_REG_LVT_ERROR, value);
            break;
 
        case APIC_REG_TIMER_ICR:
            
            apic->timer_icr = value;
            relm_vapic_sync_reg(apic, APIC_REG_TIMER_ICR, value);
            if(value != 0)
            {
                /* Capture the start time with nanosecond precision */
                apic->timer_start_ns = ktime_get_ns();
                pr_info("RELM: APIC: timer STARTED — ICR=0x%08x mode=%u "
                        "vector=0x%02x %s\n",
                        value,
                        apic->timer_mode,
                        apic->lvt_timer & APIC_LVT_VECTOR_MASK,
                        (apic->lvt_timer & APIC_LVT_MASKED) ?
                            "MASKED" : "will fire interrupt");
            }
            else
            {
                /* Writing 0 to ICR stops the timer immediately.
                 * Clear the start timestamp so CCR reads return 0. */
                apic->timer_start_ns = 0;
                PDEBUG("RELM: APIC: timer STOPPED (ICR = 0)\n");
            }
            break;
 
        case APIC_REG_TIMER_CCR:
            /* Current Count Register is READ-ONLY.
             * "Writing to this register is ignored." We comply. */
            PDEBUG("RELM: APIC: write to read-only CCR (ignored)\n");
            break;
 
        case APIC_REG_TIMER_DCR:

            apic->timer_dcr = value & 0x0BU;
            relm_vapic_sync_reg(apic, APIC_REG_TIMER_DCR, apic->timer_dcr);
            PDEBUG("RELM: APIC: timer DCR = 0x%02x\n", apic->timer_dcr);
            break;
 
        default:

            pr_warn("RELM: APIC: write to reserved/unknown offset 0x%03x "
                    "val=0x%08x (ignored)\n", offset, value);

            return -EINVAL;
    } 

    return 0;
}


/*this is the entry point called by hadle_vmexit() in cmexit.c 
* when exit reason == EXIT_REASON_APIC_ACCESS (44)
* for write (type 1), qe still need to know what value was written. 
* the hardware doesn;t tell us this directly, it only tells us  the 
* address and direction. the value is in one of the
* guest's general-purpose registers. 
* 
* we assume the value is in RAX */ 


int relm_apic_handle_access(struct vcpu *vcpu)
{
    struct virt_apic *apic = &vcpu->apic; 

    uint64_t qual; 
    uint32_t offset; 
    uint32_t access_type; 
    uint32_t value; 
    uint64_t instr_len; 
    uint64_t guest_rip; 
    int ret; 

    qual = __vmread(VM_EXIT_QUALIFICATION); 
    offset = (uint32_t)(qual & APIC_ACCESS_OFFSET_MASK); 
    access_type = (uint32_t)((qual & APIC_ACCESS_TYPE_MASK) 
        >> APIC_ACCESS_TYPE_SHIFT); 

    guest_rip = __vmread(GUEST_RIP); 
    instr_len = __vmread(VM_EXIT_INSTRUCTION_LEN); 

    PDEBUG("RELM: APIC ACCESS: offset=0x%03x type=%u RIP=0x%llx len=%llu\n",
           offset, access_type, guest_rip, instr_len);
    
    switch(access_type)
    {
        case APIC_ACCESS_TYPE_LINEAR_WRITE:

        case APIC_ACCESS_TYPE_EVENT_DELIVERY:
            
            value = (uint32_t)(vcpu->regs.rax & 0xFFFFFFFFULL);
            ret   = relm_apic_write(vcpu, offset, value);
            if(ret < 0)
                pr_warn("RELM: APIC: write to invalid offset 0x%03x "
                        "val=0x%08x at RIP=0x%llx\n",
                        offset, value, guest_rip);
            break; 

        case APIC_ACCESS_TYPE_LINEAR_READ:
            
            ret = relm_apic_read(vcpu, offset, &value);
            if(ret < 0)
            {
                pr_warn("RELM: APIC: read from invalid offset 0x%03x "
                        "at RIP=0x%llx\n", offset, guest_rip);
                value = 0;  /* return 0 for unknown registers rather than crashing */
            }

            /*inject read into guest rax*/ 
            vcpu->regs.rax = (unsigned long)(value & 0xFFFFFFFFUL);
            break;

        case APIC_ACCESS_TYPE_LINEAR_FETCH:

            /*invalid */ 
            pr_err("RELM: APIC: INSTRUCTION FETCH at APIC offset=0x%03x "
                   "RIP=0x%llx — guest instruction pointer in APIC space! "
                   "This indicates a fatal guest error.\n",
                   offset, guest_rip);
            vcpu->state = VCPU_STATE_STOPPED;
            return 0;  /* return 0 tells relm_vcpu_loop to break */

        default:
         
            PDEBUG("RELM: APIC: event-delivery access type=%u offset=0x%03x\n",
                   access_type, offset);
            ret = relm_apic_read(vcpu, offset, &value);
            if(ret == 0)
                vcpu->regs.rax = (unsigned long)(value & 0xFFFFFFFFUL);
            break;
    }

    _vmwrite(GUEST_RIP, guest_rip + instr_len);
 
    PDEBUG("RELM: APIC: handled — RIP advanced 0x%llx → 0x%llx (instr_len=%llu)\n",
           guest_rip, guest_rip + instr_len, instr_len);


    return 1; 
}
