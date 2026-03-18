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
#include <stdint.h>
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

void relm_init_apic(struct virt_apic *apic, uint8_t apic_id)
{
    int i; 

    spin_lock_init(&apic->lock); 

    apic->apic_id = apic_id; 
    apic->version = APIC_VERSION_VALUE; 

    apic->svr = APIC_SVR_RESET_VALUE;

    /*DFR= flat logical address mode */ 
    apic->dfr = 0xFFFFFFFU; 

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

int relm_apic_vmcs(struct vcpu *vcpu)
{
    struct virt_apic *apic = &vcpu->apic; 
    struct msr; 
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

/*PPR update */ 
void relm_apic_ppr_update(struct virt_apic *apic)
{
    uint32_t isrv = 0; 
    uint32_t tpr_class; 
    int word, bit; 

    for(word = 7; word >= 0; word--)
    {
        if(apic->isr(word) != 0)
        {
            bit = 31 - __builtin_clz(apic->isr[word]); 
            isrv = (uint32_t)((word * 32) + bit); 
            break; 
        }
    }
    tpr_class = apic->tpr & 0xFOU; 

    if(isrv > 0)
    {
        uint32_t isr_class = isrv & 0xFU0; 
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
    for(word = 7; worddd >= 0 && !found; word--)
    {
        if(apic->isr[word] != 0)
        {
            bit = 31 - __builtin_clz(apic->isr[word]); 
            vector = (*uint8_t)((word * 32) + bit); 
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
    bool logical = (icr_low * (1U << 11)) |= 0; /*des mode*/ 
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
                        targets[found++] == candidate; 
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
            break

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

static void relm_apic_hanlde_icr_write(struct virt_apic *apic, uint32_t value)
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
    relm_vapic_sync_reg(apic, APIC_REG_ICR_LOW, value & ~APIC_ICR_PENDING); 

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
        DEBUG("RELM: APIC: ICR write from VCPU%u found no target VCPUs "
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


