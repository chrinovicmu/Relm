#include <linux/types.h>
#include <vmcs_state.h> 
#include <vmx.h> 
#include <vmx_ops.h> 
#include <vmexit.h> 

int handle_vmexit(struct stack_guest_gprs *guest_gprs)
{
    struct vcpu *vcpu;
    uint64_t exit_reason;
    uint64_t exit_qualification;
    uint64_t guest_rip;
    uint64_t guest_rsp;
    uint64_t instr_len;

    vcpu = relm_get_current_vcpu();
    if(!vcpu)
    {
        pr_err("relm: handle_vmexit called but no current VCPU!\n");
        return 0;
    }

    exit_reason = __vmread(VM_EXIT_REASON);

    /*check if VM-entry failure */
    if(exit_reason & (1ULL << 32))
    {
        pr_err("relm: [VPID=%u] VM-entry failure in exit handler\n",
               vcpu->vpid);
        return 0;
    }

    exit_qualification = __vmread(VM_EXIT_QUALIFICATION);
    guest_rip = __vmread(GUEST_RIP);
    guest_rsp = __vmread(GUEST_RSP);

    vcpu->stats.total_exits++;

    if(!vcpu->launched)
    {
        vcpu->launched = 1;
        pr_info("relm: [VPID=%u] First VM-exit (exit #%llu), now using VMRESUME\n",
                vcpu->vpid, vcpu->stats.total_exits);
    }

    vcpu->regs.rax = guest_gprs->rax;
    vcpu->regs.rbx = guest_gprs->rbx;
    vcpu->regs.rcx = guest_gprs->rcx;
    vcpu->regs.rdx = guest_gprs->rdx;
    vcpu->regs.rsi = guest_gprs->rsi;
    vcpu->regs.rdi = guest_gprs->rdi;
    vcpu->regs.rbp = guest_gprs->rbp;
    vcpu->regs.r8  = guest_gprs->r8;
    vcpu->regs.r9  = guest_gprs->r9;
    vcpu->regs.r10 = guest_gprs->r10;
    vcpu->regs.r11 = guest_gprs->r11;
    vcpu->regs.r12 = guest_gprs->r12;
    vcpu->regs.r13 = guest_gprs->r13;
    vcpu->regs.r14 = guest_gprs->r14;
    vcpu->regs.r15 = guest_gprs->r15;

    vcpu->regs.rsp = guest_rsp;
    vcpu->regs.rip = guest_rip;

    PDEBUG("relm: [VPID=%u] Exit #%llu: reason=%llu RIP=0x%llx\n",
           vcpu->vpid, vcpu->stats.total_exits, exit_reason, guest_rip);

    switch(exit_reason)
    {
        case EXIT_REASON_EXCEPTION_NMI:
        {
            uint32_t intr_info = __vmread(VM_EXIT_INTR_INFO);
            uint32_t vector = intr_info & 0xFF;
            uint32_t intr_type = (intr_info >> 8) & 0x7;

            pr_err("relm: [VPID=%u] Guest exception: vector=%u type=%u at RIP=0x%llx\n",
                   vcpu->vpid, vector, intr_type, guest_rip);

            /*treat all exceptions as fatal */
            vcpu->state = VCPU_STATE_STOPPED;
            return 0;
        }

        case EXIT_REASON_EXTERNAL_INTERRUPT:

            /* external interrupt arrived while guest was running
            * just re-enter the guest */
            PDEBUG("relm: [VPID=%u] External interrupt\n", vcpu->vpid);
            return 1;

        case EXIT_REASON_TRIPLE_FAULT:

            pr_err("relm: [VPID=%u] Guest triple fault at RIP=0x%llx\n",
                   vcpu->vpid, guest_rip);
            vcpu->state = VCPU_STATE_STOPPED;
            return 0;

        case EXIT_REASON_INIT_SIGNAL:

            pr_info("relm: [VPID=%u] INIT signal received\n", vcpu->vpid);
            vcpu->state = VCPU_STATE_STOPPED;
            return 0;

        case EXIT_REASON_HLT:

            pr_info("relm: [VPID=%u] Guest executed HLT at RIP=0x%llx\n",
                    vcpu->vpid, guest_rip);
            vcpu->halted = true;
            vcpu->state = VCPU_STATE_HALTED;

            instr_len = __vmread(VM_EXIT_INSTRUCTION_LEN);
            _vmwrite(GUEST_RIP, guest_rip + instr_len);

            /* stop execution on HLT */
            return 0;

        case EXIT_REASON_CPUID:
        {
            uint32_t leaf = vcpu->regs.rax & 0xFFFFFFFF;
            uint32_t subleaf = vcpu->regs.rcx & 0xFFFFFFFF;
            uint32_t eax, ebx, ecx, edx;

            PDEBUG("relm: [VPID=%u] CPUID leaf=0x%x subleaf=0x%x\n",
                   vcpu->vpid, leaf, subleaf);

            __asm__ volatile(
                "cpuid"
                : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                : "a"(leaf), "c"(subleaf)
            );

            guest_gprs->rax = eax;
            guest_gprs->rbx = ebx;
            guest_gprs->rcx = ecx;
            guest_gprs->rdx = edx;

            vcpu->regs.rax = eax;
            vcpu->regs.rbx = ebx;
            vcpu->regs.rcx = ecx;
            vcpu->regs.rdx = edx;

            instr_len = __vmread(VM_EXIT_INSTRUCTION_LEN);
            _vmwrite(GUEST_RIP, guest_rip + instr_len);

            return 1;
        }

        case EXIT_REASON_IO_INSTRUCTION:
        {
            bool is_in = (exit_qualification & (1ULL << 3)) != 0;
            bool is_string = (exit_qualification & (1ULL << 4)) != 0;
            bool is_rep = (exit_qualification & (1ULL << 5)) != 0;
            uint32_t size = (exit_qualification & 0x7) + 1;
            uint16_t port = (exit_qualification >> 16) & 0xFFFF;

            pr_info("relm: [VPID=%u] I/O %s%s%s port=0x%x size=%u at RIP=0x%llx\n",
                    vcpu->vpid,
                    is_in ? "IN" : "OUT",
                    is_string ? " STRING" : "",
                    is_rep ? " REP" : "",
                    port, size, guest_rip);

            /*TODO: emulate device or forward to userspace
             * emulate as NOP for now*/
            instr_len = __vmread(VM_EXIT_INSTRUCTION_LEN);
            _vmwrite(GUEST_RIP, guest_rip + instr_len);

            return 1;
        }

        case EXIT_REASON_VMCALL:

            pr_info("relm: [VPID=%u] VMCALL hypercall at RIP=0x%llx\n",
                    vcpu->vpid, guest_rip);

            /*TODO: implement hypercall
            * advance RIP for now*/
            instr_len = __vmread(VM_EXIT_INSTRUCTION_LEN);
            _vmwrite(GUEST_RIP, guest_rip + instr_len);
            return 1;

        case EXIT_REASON_MSR_READ:
        {
            uint32_t msr = vcpu->regs.rcx & 0xFFFFFFFF;
            pr_info("relm: [VPID=%u] RDMSR 0x%x at RIP=0x%llx\n",
                    vcpu->vpid, msr, guest_rip);

            /*TODO: emulate MSR_READ
             * pass 0 for now*/
            guest_gprs->rax = 0;
            guest_gprs->rdx = 0;
            vcpu->regs.rax = 0;
            vcpu->regs.rdx = 0;

            instr_len = __vmread(VM_EXIT_INSTRUCTION_LEN);
            _vmwrite(GUEST_RIP, guest_rip + instr_len);
            return 1;
        }

        case EXIT_REASON_MSR_WRITE:
        {
            uint32_t msr = vcpu->regs.rcx & 0xFFFFFFFF;
            uint64_t value = ((uint64_t)vcpu->regs.rdx << 32) | (vcpu->regs.rax & 0xFFFFFFFF);

            pr_info("relm: [VPID=%u] WRMSR 0x%x = 0x%llx at RIP=0x%llx\n",
                    vcpu->vpid, msr, value, guest_rip);

            /*TODO: emulate MSR write
             * advance RIP for now*/
            instr_len = __vmread(VM_EXIT_INSTRUCTION_LEN);
            _vmwrite(GUEST_RIP, guest_rip + instr_len);

            return 1;
        }

        case EXIT_REASON_EPT_VIOLATION:
        {
            uint64_t gpa = __vmread(GUEST_PHYSICAL_ADDRESS);
            bool data_read = exit_qualification & (1ULL << 0);
            bool data_write = exit_qualification & (1ULL << 1);
            bool instr_fetch = exit_qualification & (1ULL << 2);
            bool ept_readable = exit_qualification & (1ULL << 3);
            bool ept_writable = exit_qualification & (1ULL << 4);
            bool ept_executable = exit_qualification & (1ULL << 5);

            pr_err("relm: [VPID=%u] EPT violation at GPA 0x%llx\n",
                   vcpu->vpid, gpa);

            pr_err(" Access: %s%s%s at RIP=0x%llx\n",
                   data_read ? "R" : "",
                   data_write ? "W" : "",
                   instr_fetch ? "X" : "",
                   guest_rip);

            pr_err(" EPT entry: %s%s%s\n",
                   ept_readable ? "R" : "-",
                   ept_writable ? "W" : "-",
                   ept_executable ? "X" : "-");

            vcpu->state = VCPU_STATE_STOPPED;
            return 0;
        }

        case EXIT_REASON_INVALID_GUEST_STATE:

            pr_err("relm: [VPID=%u] Invalid guest state\n", vcpu->vpid);
            pr_err(" Guest RIP: 0x%llx\n", guest_rip);
            pr_err(" Guest RSP: 0x%llx\n", guest_rsp);

            relm_dump_vcpu(vcpu);

            vcpu->state = VCPU_STATE_STOPPED;
            return 0;

        default:

            pr_err("relm: [VPID=%u] Unhandled VM-exit reason %llu\n",
                   vcpu->vpid, exit_reason);
            pr_err(" Guest RIP: 0x%llx\n", guest_rip);
            pr_err(" Exit qualification: 0x%llx\n", exit_qualification);

            vcpu->state = VCPU_STATE_STOPPED;
            return 0;
    }
}

