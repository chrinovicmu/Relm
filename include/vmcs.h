#ifndef VMCS_H
#define VMCS_H


struct vmcs{
    u32 revision_id;
    u32 abort;
    char data[0]
}__aligned(CONFIG_X86_PAGE_SIZE); 

struct vmxon_region{
    u32 revision_id; 
    u32 reserved; 
    char data[0]; 
}__aligned(CONFIG_X86_PAGE_SIZE); 

/*handles aynchornous events (interrupts) */ 
struct vmx_pinbased_ctls{

    u32 control;

    struct
    {
        u32 external_interrupt_exiting  : 1;
        u32 reserved1                   : 2; 
        u32 nmi_exiting                 : 1;
        u32 reserved2                   : 1;
        u32 virtual_nmis                : 1;
        u32 vmx_preemption_timer        : 1; 
        u32 process_posted_interrupts    : 1; 
        u32 reserved                    : 24; 
    } bits; 
};

struct vmx_procbased_ctls_prim {
    u32 control;

    struct {
        u32 reserved0_1                 : 2;
        u32 interrupt_window_exiting    : 1;
        u32 use_tsc_offsetting          : 1;
        u32 reserved4_7                 : 4;
        u32 hlt_exit                    : 1;
        u32 invlpg_exit                 : 1;
        u32 mwait_exit                  : 1;
        u32 rdpmc_exit                  : 1;
        u32 rdtsc_exit                  : 1;
        u32 reserved13_14               : 2;
        u32 cr3_load_exit               : 1;
        u32 cr3_store_exit              : 1;
        u32 reserved17                  : 1;
        u32 cr8_load_exit               : 1;
        u32 cr8_store_exit              : 1;
        u32 use_tpr_shadow              : 1;
        u32 nmi_window_exiting          : 1;
        u32 mov_dr_exit                 : 1;
        u32 unconditional_io_exiting    : 1;
        u32 use_io_bitmaps              : 1;
        u32 monitor_trap_flag           : 1;
        u32 use_msr_bitmaps             : 1;
        u32 monitor_exit                : 1;
        u32 pause_exit                  : 1;
        u32 reserved30_31               : 2;
    };
};

struct vmx_procbased_ctls_sec {
    u32 control;

    struct {
        u32 virtualize_apic_accesses        : 1;
        u32 enable_ept                      : 1;
        u32 descriptor_table_exiting        : 1;
        u32 enable_rdtscp                   : 1;
        u32 virtualize_x2apic_mode          : 1;
        u32 enable_vpid                     : 1;
        u32 wbinvd_exit                     : 1;
        u32 unrestricted_guest              : 1;
        u32 apic_register_virtualization    : 1;
        u32 virtual_interrupt_delivery      : 1;
        u32 pause_loop_exiting              : 1;
        u32 rdrand_exit                     : 1;
        u32 enable_invpcid                  : 1;
        u32 enable_vm_functions             : 1;
        u32 vmcs_shadowing                  : 1;
        u32 enable_encls_exit               : 1;
        u32 rdseed_exit                     : 1;
        u32 enable_pml                      : 1;
        u32 ept_violation                   : 1;
        u32 conceal_vmx_from_guest          : 1;
        u32 enable_xsave_xrstor             : 1;
        u32 mode_based_execution_controls   : 1;
        u32 reserved22_31                   : 10;
    };
};

struct vmx_vmexit_ctls {
    u32 control;

    struct {
        u32 reserved0_1                 : 2;
        u32 save_debug_controls          : 1;
        u32 reserved3                    : 1;
        u32 host_address_space_size      : 1;
        u32 reserved5                    : 1;
        u32 load_ia32_perf_global_ctrl   : 1;
        u32 reserved7                    : 1;
        u32 ack_interrupt_on_exit         : 1;
        u32 save_ia32_pat                 : 1;
        u32 load_ia32_pat                 : 1;
        u32 save_ia32_efer                : 1;
        u32 load_ia32_efer                : 1;
        u32 save_ve                        : 1;
        u32 clear_ve                       : 1;
        u32 reserved15_31                  : 17;
    };
};

struct vmx_vmentry_ctls {
    u32 control;

    struct {
        u32 reserved0_1                : 2;
        u32 load_debug_controls         : 1;
        u32 reserved3_4                 : 2;
        u32 ia32e_mode_guest            : 1;
        u32 entry_to_smm                : 1;
        u32 deactivate_dual_monitor      : 1;
        u32 reserved8_9                 : 2;
        u32 load_ia32_perf_global_ctrl  : 1;
        u32 reserved11                  : 1;
        u32 load_ia32_pat                : 1;
        u32 load_ia32_efer               : 1;
        u32 load_ia32_bndcfgs             : 1;
        u32 reserved15_31                : 17;
    };
};

/*processpr-based vm execution controls */ 


/*vm-execution controls govern VMX non-root operation */ 

struct vmx_vmexec_controls
{
    struct vmx_pinbased_ctls pin;
    struct vmx_procbased_ctls_prim primary;
    struct vmx_procbased_ctls_sec secondary;
    struct vmx_vmexit_clts exit;
    struct vmx_entry_ctls entry; 
}; 
