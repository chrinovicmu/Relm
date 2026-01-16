#ifndef VMCS_STATE_H 
#define VMCS_STATE_H

#define HOST_CR0		                0x00006c00
#define	HOST_CR3		                0x00006c02
#define	HOST_CR4		                0x00006c04

#define HOST_RSP						0x00006c14
#define	HOST_RIP						0x00006c16

#define HOST_ES_SELECTOR				0x00000c00
#define HOST_CS_SELECTOR				0x00000c02
#define HOST_SS_SELECTOR				0x00000c04
#define HOST_DS_SELECTOR				0x00000c06
#define HOST_FS_SELECTOR				0x00000c08
#define HOST_GS_SELECTOR				0x00000c0a
#define HOST_TR_SELECTOR				0x00000c0c
#define HOST_FS_BASE					0x00006c06
#define HOST_GS_BASE					0x00006c08
#define HOST_TR_BASE					0x00006c0a
#define HOST_GDTR_BASE					0x00006c0c
#define HOST_IDTR_BASE					0x00006c0e

#define HOST_IA32_SYSENTER_ESP			0x00006c10
#define HOST_IA32_SYSENTER_EIP			0x00006c12
#define HOST_IA32_SYSENTER_CS			0x00004c00
#define HOST_SYSENTER_CS                0x00006C0C
#define HOST_SYSENTER_ESP               0x00006C0E
#define HOST_SYSENTER_EIP               0x00006C10
#define GUEST_CR0						0x00006800
#define GUEST_CR3						0x00006802
#define GUEST_CR4						0x00006804

#define	GUEST_RSP						0x0000681c
#define	GUEST_RIP						0x0000681e
#define GUEST_RFLAGS                    0x00006820
#define MSR_IA32_CR_PAT					0x00000277
#define MSR_EFER						0xc0000080
#define MSR_CORE_PERF_GLOBAL_CTRL		0x0000038f
#define HOST_IA32_PAT					0x00002c00
#define HOST_IA32_EFER					0x00002c02
#define HOST_IA32_PERF_GLOBAL_CTRL		0x00002c04

#define GUEST_ES_SELECTOR				0x00000800
#define GUEST_CS_SELECTOR				0x00000802
#define GUEST_SS_SELECTOR				0x00000804
#define GUEST_DS_SELECTOR				0x00000806
#define GUEST_FS_SELECTOR				0x00000808
#define GUEST_GS_SELECTOR				0x0000080a
#define GUEST_LDTR_SELECTOR				0x0000080c
#define GUEST_TR_SELECTOR				0x0000080e
#define GUEST_ES_LIMIT					0x00004800
#define GUEST_CS_LIMIT					0x00004802
#define GUEST_SS_LIMIT					0x00004804
#define GUEST_DS_LIMIT					0x00004806
#define GUEST_FS_LIMIT					0x00004808
#define GUEST_GS_LIMIT					0x0000480a
#define GUEST_LDTR_LIMIT				0x0000480c
#define GUEST_TR_LIMIT					0x0000480e
#define GUEST_GDTR_LIMIT				0x00004810
#define GUEST_IDTR_LIMIT				0x00004812
#define GUEST_ES_AR_BYTES				0x00004814
#define GUEST_CS_AR_BYTES				0x00004816
#define GUEST_SS_AR_BYTES				0x00004818
#define GUEST_DS_AR_BYTES				0x0000481a
#define GUEST_FS_AR_BYTES				0x0000481c
#define GUEST_GS_AR_BYTES				0x0000481e
#define GUEST_LDTR_AR_BYTES				0x00004820
#define GUEST_TR_AR_BYTES				0x00004822
#define GUEST_ES_BASE					0x00006806
#define GUEST_CS_BASE					0x00006808
#define GUEST_SS_BASE					0x0000680a
#define GUEST_DS_BASE					0x0000680c
#define GUEST_FS_BASE					0x0000680e
#define GUEST_GS_BASE					0x00006810
#define GUEST_LDTR_BASE					0x00006812
#define GUEST_TR_BASE					0x00006814
#define GUEST_GDTR_BASE					0x00006816
#define GUEST_IDTR_BASE                 0x00006818 
#define GUEST_DR7                       0x0000681a
#define GUEST_IA32_DEBUGCTL				0x00002802
#define GUEST_IA32_PAT					0x00002804
#define GUEST_IA32_EFER					0x00002806
#define GUEST_IA32_PERF_GLOBAL_CTRL		0x00002808
#define GUEST_SYSENTER_CS				0x0000482A
#define GUEST_SYSENTER_ESP				0x00006824
#define GUEST_SYSENTER_EIP				0x00006826

#define GUEST_PDPTE0                    0X0000280a 
#define GUEST_PDPTE(n)  (GUEST_PDPTE0 + (n) * 2)
/*guest non-register state */ 

#define GUEST_ACTIVITY_STATE			0X00004826
#define VMX_PREEMPTION_TIMER_VALUE		0x0000482E
#define VMCS_LINK_POINTER				0x00002800
#define GUEST_INTR_STATUS				0x00000810
#define GUEST_PML_INDEX					0x00000812

#define HOST_STACK_ORDER                2 
#define GUEST_STACK_SIZE                64 

struct desc64 {
	uint16_t limit0;
	uint16_t base0;
	unsigned base1:8, s:1, type:4, dpl:2, p:1;
	unsigned limit1:4, avl:1, l:1, db:1, g:1, base2:8;
	uint32_t base3;
	uint32_t zero1;
} __attribute__((packed));

static inline uint16_t get_es1(void)
{
	uint16_t es;

	__asm__ __volatile__ (
        "mov %%es, %[es]"
		:[es]"=rm"(es)
    );

	return es;
}

static inline uint16_t get_cs1(void)
{
	uint16_t cs;

	__asm__ __volatile__ (
        "mov %%cs, %[cs]"
		:[cs]"=rm"(cs)
    );

	return cs;
}

static inline uint16_t get_ss1(void)
{
	uint16_t ss;

	__asm__ __volatile__ (
        "mov %%ss, %[ss]"
		:[ss]"=rm"(ss)
    );

	return ss;
}

static inline uint16_t get_ds1(void)
{
	uint16_t ds;

	__asm__ __volatile__ (
        "mov %%ds, %[ds]"
		:[ds]"=rm"(ds));

	return ds;
}

static inline uint16_t get_fs1(void)
{
	uint16_t fs;

	__asm__ __volatile__ (
        "mov %%fs, %[fs]"
		:[fs]"=rm"(fs)
    );

	return fs;
}

static inline uint16_t get_gs1(void)
{
	uint16_t gs;

	__asm__ __volatile__ (
        "mov %%gs, %[gs]"
		:[gs]"=rm"(gs)
    );

	return gs;
}

static inline uint16_t get_tr1(void)
{
	uint16_t tr;

	__asm__ __volatile__ (
        "str %[tr]"
		:[tr]"=rm"(tr)
    );

	return tr;
}

static inline uint64_t get_gdt_base1(void)
{
	struct desc_ptr gdt;

	__asm__ __volatile__(
        "sgdt %[gdt]"
		: [gdt]"=m"(gdt)
    );

	return gdt.address;
}

static inline uint64_t get_idt_base1(void)
{
	struct desc_ptr idt;

	__asm__ __volatile__(
        "sidt %[idt]"
		: [idt]"=m"(idt)
    );

	return idt.address;
}

static inline uint64_t get_desc64_base(const struct desc64 *desc)
{
	return ((uint64_t)desc->base3 << 32) |
		(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

#endif  
