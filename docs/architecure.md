# Relm Hypervisor Architecture


## Overview

Relm is a Type-1 hypervisor running in the linux kernel as a kernel module. It uses Intel VMX (Virtual Machine Extensions) to run a single guest virtual machine with one or more virtual CPUs (VCPUs) directly on hardware, with hardware-accelerated memory isolation via Intel EPT (Extended Page Tables).

This document describes the system from the top down: module lifecycle, component structure, data flow between components, and the hardware interfaces that each component touches.

---

## Privilege Levels and Execution Modes

Intel VMX introduces two orthogonal execution modes:

```
┌─────────────────────────────────────────────────────────────────────┐
│  VMX Root Operation  (host mode)                                    │
│                                                                     │
│  Ring 0: Linux kernel + Relm module                                 │
│    - Full hardware access                                           │
│    - Controls VMX via VMXON/VMXOFF/VMLAUNCH/VMRESUME               │
│    - Handles VM-exits                                               │
│                                                                     │
│  Ring 3: Host userspace (normal Linux processes)                    │
│    - Unrelated to Relm; runs normally                               │
└─────────────────────────────────────────────────────────────────────┘
         ▲                    │
         │  VM-exit           │  VM-entry (VMLAUNCH / VMRESUME)
         │                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  VMX Non-Root Operation  (guest mode)                               │
│                                                                     │
│  Ring 0: Guest kernel (if any)                                      │
│  Ring 3: Guest userspace                                            │
│                                                                     │
│    - Restricted hardware access                                     │
│    - Certain instructions / events cause VM-exits                   │
│    - Memory accesses translated through EPT                         │
└─────────────────────────────────────────────────────────────────────┘
```

Relm code runs exclusively in VMX root mode. Guest code runs exclusively in VMX non-root mode. The transition between them is managed by VMLAUNCH/VMRESUME (host → guest) and hardware-triggered VM-exits (guest → host).

---

## Component Map

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Relm Kernel Module                                                      │
│                                                                          │
│  ┌──────────────┐    ┌──────────────────────────────────────────────┐   │
│  │  module.c    │    │  vm.c / vm.h                                 │   │
│  │              │    │                                              │   │
│  │  module_init ├───▶│  relm_create_vm()                           │   │
│  │  module_exit │    │  relm_destroy_vm()                          │   │
│  │              │    │  relm_vm_add_vcpu()                         │   │
│  └──────────────┘    │  relm_run_vm()  ──────────────────────────┐ │   │
│                       │  relm_stop_vm()                           │ │   │
│                       │  relm_vm_allocate_guest_ram()             │ │   │
│                       │  relm_vm_copy_to_guest()                  │ │   │
│                       │  relm_vm_create_guest_page_tables()       │ │   │
│                       └──────────────────────────────────────────┼─┘   │
│                                                                   │      │
│  ┌────────────────────────────────────────────────────────────┐  │      │
│  │  vmx.c / vmx.h                                             │  │      │
│  │                                                            │◀─┘      │
│  │  relm_vmx_enable_on_all_cpus()                             │         │
│  │  relm_vcpu_alloc_init()       [Phase 1: memory]           │         │
│  │  relm_vcpu_pin_to_cpu()       [affinity]                  │         │
│  │  relm_vcpu_vmcs_setup()       [Phase 2: VMX]              │         │
│  │  relm_init_vmcs_state()       [VMCS host+guest regs]      │         │
│  │  relm_vcpu_loop()             [kthread: entry loop]       │         │
│  │  relm_vmentry_asm()           [assembly: VMLAUNCH/RESUME] │         │
│  │  relm_vmexit_handler()        [assembly: VM-exit stub]    │         │
│  └────────────────────────┬───────────────────────────────────┘         │
│                            │                                             │
│  ┌─────────────────────────▼──────────────────────────────────────┐     │
│  │  ept.c / ept.h                                                  │     │
│  │                                                                 │     │
│  │  relm_ept_check_support()                                       │     │
│  │  relm_setup_ept()              builds EPT page table tree       │     │
│  │  relm_ept_map_page()           maps GPA → HPA in EPT           │     │
│  │  relm_ept_context_destroy()    frees EPT tree                  │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  vmexit.c / vmexit.h                                             │    │
│  │                                                                  │    │
│  │  relm_handle_vmexit()         C dispatch for exit reasons       │    │
│  │  relm_handle_cpuid()                                             │    │
│  │  relm_handle_hlt()                                               │    │
│  │  relm_handle_ept_violation()                                     │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  vmx_ops.h / vmcs.h                                              │    │
│  │                                                                  │    │
│  │  __vmread() / __vmwrite()     inline VMREAD/VMWRITE wrappers    │    │
│  │  _vmcs_revision_id()          reads MSR_IA32_VMX_BASIC          │    │
│  │  _cpu_has_vpid()              checks CPUID for VPID support     │    │
│  │  VMCS field encodings         (all VMCS field constants)        │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Core Data Structures

The entire system is built around three primary structs with a clear ownership hierarchy:

```
struct relm_vm
│
│  Owns:
│  ├── struct ept_context *ept          One EPT tree for the whole VM
│  ├── struct guest_mem_region *mem_regions  Linked list of guest RAM regions
│  ├── uint64_t pml4_gpa               GPA of guest PML4 (set by create_guest_page_tables)
│  ├── struct vcpu **vcpus[]           Array of VCPU pointers [0..max_vcpus-1]
│  ├── struct relm_vm_stats stats      Exit counters, timing
│  └── spinlock_t lock                 Protects state transitions
│
└── struct vcpu  (one per VCPU slot)
    │
    │  Owns:
    │  ├── struct vmcs_region *vmcs       4KB VMCS region (hardware-managed)
    │  ├── void *host_stack              16KB kthread stack
    │  ├── uint8_t *io_bitmap            8KB IO port intercept bitmap
    │  ├── void *msr_bitmap              4KB MSR intercept bitmap
    │  ├── struct msr_entry *vmexit_store_area   MSR store list
    │  ├── struct msr_entry *vmexit_load_area    MSR load list (exit)
    │  ├── struct msr_entry *vmentry_load_area   MSR load list (entry)
    │  ├── struct guest_regs regs        Snapshot of guest GPRs
    │  ├── struct vmx_exec_ctrls controls  Pin/proc/exit/entry control values
    │  ├── struct task_struct *host_task  Kthread running this VCPU
    │  └── struct host_cpu *hcpu         Physical CPU this VCPU is pinned to
    │
    └── struct host_cpu  (one per physical CPU, per-CPU variable)
        │
        │  Owns:
        │  └── struct vmxon_region *vmxon   4KB VMXON region
```

### Relationship Rules

- One `relm_vm` contains one `ept_context` shared by all VCPUs.
- One `relm_vm` contains up to `Relm_MAX_VCPUS` VCPUs (currently 1).
- One `vcpu` is pinned to exactly one physical CPU, identified by `vcpu->target_cpu_id`.
- One `host_cpu` is associated with exactly one physical CPU (stored in `DEFINE_PER_CPU(relm_per_cpu_hcpu)`).
- The `vcpu → host_cpu` association is established in `relm_vcpu_loop` after pinning.

---

## Module Lifecycle

```
insmod relm.ko
      │
      ▼
module_init()
  │
  ├── relm_vmx_enable_on_all_cpus()
  │     Phase A (sleepable):
  │       for each online CPU:
  │         kzalloc(host_cpu)
  │         __get_free_page → VMXON region, write revision ID
  │         per_cpu(relm_per_cpu_hcpu, cpu) = hcpu
  │     Phase B (IPI, atomic):
  │       on_each_cpu:
  │         set CR4.VMXE
  │         configure IA32_FEATURE_CONTROL MSR
  │         VMXON(vmxon_pa)
  │         [all CPUs now in VMX root operation]
  │
  ├── relm_create_vm(vm_id, name, ram_size)
  │     relm_ept_check_support()       verify EPT capability
  │     relm_setup_ept(vm)             build EPT page table tree, set vm->ept->eptp
  │     relm_vm_allocate_guest_ram()   alloc_page × N, relm_ept_map_page × N
  │     relm_vm_create_guest_page_tables()  alloc PML4/PDPT/PD, identity map 1GB
  │     kcalloc(vcpus[])              allocate VCPU pointer array
  │
  ├── [optional] relm_vm_copy_to_guest()    load guest binary into GPA 0x0
  │
  ├── relm_vm_add_vcpu(vm, vpid)       Phase 1 VCPU init (memory only)
  │     relm_vcpu_alloc_init()
  │     vcpu->target_cpu_id = HOST_CPU_ID
  │     vcpu->regs.rsp = top of guest RAM
  │
  └── relm_run_vm(vm)
        for each VCPU:
          kthread_create(relm_vcpu_loop)
          wake_up_process()
          [kthread pins itself and runs Phase 2 + VM-entry loop]

      [VM runs until stop or module unload]

rmmod relm.ko  (or explicit relm_stop_vm + relm_destroy_vm)
      │
      ▼
module_exit()
  │
  ├── relm_stop_vm(vm)
  │     for each VCPU:
  │       relm_vcpu_unpin_and_stop()
  │         set_cpus_allowed_ptr(task, cpu_online_mask)  ← allow migration
  │         kthread_stop(task)
  │         [kthread exits loop, executes VMCLEAR, sets current_vcpu=NULL]
  │
  ├── relm_destroy_vm(vm)
  │     relm_vm_free_guest_mem()       __free_page × N
  │     relm_ept_context_destroy()     free EPT page table tree
  │     relm_free_vcpu()               free stack, VMCS, bitmaps, MSR areas
  │     kfree(vcpus[])
  │     kfree(vm)
  │
  └── relm_vmx_disable_on_all_cpus()
        on_each_cpu:
          VMXOFF()                     exit VMX root operation
          clear CR4.VMXE
        for each online CPU:
          free_page(vmxon)
          kfree(host_cpu)
          per_cpu(relm_per_cpu_hcpu, cpu) = NULL
```

---

## VM Creation Flow

`relm_create_vm()` sets up the VM's memory subsystem in the order dictated by dependency:

```
1. relm_ept_check_support()
   Read CPUID.1:ECX[5] (VMX support) and IA32_VMX_PROCBASED_CTLS2 bit 1 (EPT).
   Without EPT, memory isolation is not hardware-accelerated; abort.

2. relm_setup_ept(vm)
   Create the EPT page table tree (PML4 → PDPT → PD → PT hierarchy in host memory).
   Store the computed EPTP value in vm->ept->eptp.
   This EPTP will be written to the VMCS EPT_POINTER field during VCPU Phase 2.

3. relm_vm_allocate_guest_ram(vm, size, gpa_start=0)
   For each 4KB page of guest RAM:
     - alloc_page(GFP_KERNEL | __GFP_ZERO)
     - store in region->pages[i]
     - relm_ept_map_page(vm->ept, gpa, hpa, EPT_RWX)
   Add region to vm->mem_regions list.

4. relm_vm_create_guest_page_tables(vm)
   Allocate 3 separate pages: PML4, PDPT, PD.
   Map them into EPT.
   Fill PML4[0] → PDPT → PD → 512 × 2MB identity-map entries.
   Store vm->pml4_gpa = address of PML4 page.
   This GPA will be written to VMCS GUEST_CR3 during VCPU Phase 2.
```

---

## VCPU Creation and Startup

VCPU initialisation follows the two-phase model described in `vcpu_execution_model.md`. From an architecture perspective:

```
relm_vm_add_vcpu(vm, vpid)          [module_init context, sleepable]
  │
  └── relm_vcpu_alloc_init(vm, vpid)
        Allocates all VCPU memory.
        Sets vcpu->target_cpu_id = HOST_CPU_ID.
        Sets vcpu->cr3 = vm->pml4_gpa.
        Returns vcpu with state = VCPU_STATE_INITIALIZED.

relm_run_vcpu(vm, vpid)             [module_init context, sleepable]
  │
  └── kthread_create(relm_vcpu_loop, vcpu, "relm_vm%d_vpid%u")
      wake_up_process(vcpu->host_task)

      [kthread runs relm_vcpu_loop on scheduler-chosen CPU]
        pin → Phase 2 VMCS setup → init_vmcs_state → VM-entry loop
```

The key architectural property: the caller of `relm_run_vcpu` returns immediately after `wake_up_process`. The kthread runs independently and performs all VMX work autonomously. Module init does not wait for the VCPU to enter the guest.

---

## VM-Exit Handling Architecture

When the guest triggers a VM-exit the CPU transfers control to `relm_vmexit_handler` (the value in VMCS `HOST_RIP`). The handler is split across two layers:

### Layer 1 — Assembly Stub (`relm_vmexit_handler`)

Runs immediately on VM-exit, before any C code. Responsibilities:

```asm
relm_vmexit_handler:
  ; CPU has already restored:
  ;   RSP  ← HOST_RSP (vcpu->host_rsp)
  ;   RIP  ← HOST_RIP (here)
  ;   CR0/CR3/CR4 ← HOST_CR0/CR3/CR4
  ;   Segments ← HOST_CS/DS/ES/SS/FS/GS selectors
  ;   GDT/IDT/TR ← HOST_GDTR_BASE/IDTR_BASE/TR
  ;   MSRs ← vmexit_load_area values (EFER, FS_BASE, GS_BASE etc.)
  ;
  ; CPU has NOT saved: RAX, RBX, RCX, RDX, RSI, RDI, RBP, R8-R15
  ; We must save these before any C call (C ABI is caller-save for some,
  ; callee-save for others, but ALL are guest values here):

  push rax, rbx, rcx, rdx, rsi, rdi, rbp, r8-r15

  ; Get vcpu pointer from per-CPU variable
  call relm_get_current_vcpu        ; returns vcpu in rax

  ; Store saved registers into vcpu->regs
  ; (copy pushed values to vcpu->regs.rax, rbx etc.)

  ; Call C dispatch
  call relm_handle_vmexit

  ; Restore guest registers from vcpu->regs
  ; (in case dispatch modified them, e.g. for CPUID emulation)
  pop r15-r8, rbp, rdi, rsi, rdx, rcx, rbx, rax

  ; Return to relm_vmentry_asm which will execute VMRESUME
  ret
```

### Layer 2 — C Dispatch (`relm_handle_vmexit`)

Reads `VMCS VM_EXIT_REASON` and dispatches to the appropriate handler:

```
exit reason
     │
     ├── EXIT_REASON_CPUID        → relm_handle_cpuid()
     │                               emulate CPUID instruction
     │                               write result to vcpu->regs.rax/rbx/rcx/rdx
     │
     ├── EXIT_REASON_HLT          → relm_handle_hlt()
     │                               set vcpu->halted = true
     │                               advance guest RIP past HLT instruction
     │                               (optionally: schedule() to yield CPU)
     │
     ├── EXIT_REASON_EPT_VIOLATION → relm_handle_ept_violation()
     │                               read exit qualification for access type
     │                               if MMIO range: emulate device access
     │                               if unmapped: error or demand-map
     │
     ├── EXIT_REASON_MSR_READ      → emulate RDMSR
     ├── EXIT_REASON_MSR_WRITE     → emulate WRMSR
     ├── EXIT_REASON_EXCEPTION_NMI → dispatch on exception vector
     │     vector 6 (#UD)          → emulate or inject #UD back to guest
     │     vector 14 (#PF)         → page fault handling
     │
     └── (unhandled)               → log error, set VCPU_STATE_ERROR, break loop
```

After `relm_handle_vmexit` returns, control returns to the assembly stub which restores guest GPRs and returns to `relm_vmentry_asm`, which executes `VMRESUME` to re-enter the guest.

---

## Intel VMX Hardware Interface

Relm communicates with the VMX hardware through five categories of interface:

### 1. CPUID

Used to detect VMX and feature support:

| Leaf | Register | Bit | Feature |
|---|---|---|---|
| CPUID.1 | ECX | 5 | VMX support |
| CPUID.1 | ECX | 1 | VMX inside VMX (not used) |

### 2. Model-Specific Registers (MSRs)

| MSR | Usage |
|---|---|
| `IA32_FEATURE_CONTROL` (0x3A) | Enable VMXON outside SMX; lock bit |
| `IA32_VMX_BASIC` (0x480) | VMCS/VMXON revision ID; VMCS size |
| `IA32_VMX_PINBASED_CTLS` (0x481) | Pin-based control capability |
| `IA32_VMX_PROCBASED_CTLS` (0x482) | Primary proc-based control capability |
| `IA32_VMX_EXIT_CTLS` (0x483) | VM-exit control capability |
| `IA32_VMX_ENTRY_CTLS` (0x484) | VM-entry control capability |
| `IA32_VMX_MISC` (0x485) | Max CR3 targets; misc capabilities |
| `IA32_VMX_CR0_FIXED0/1` (0x486/0x487) | CR0 fixed-bit constraints |
| `IA32_VMX_CR4_FIXED0/1` (0x488/0x489) | CR4 fixed-bit constraints |
| `IA32_VMX_PROCBASED_CTLS2` (0x48B) | Secondary proc-based capability |
| `IA32_EFER` (0xC0000080) | Long mode / syscall enable |
| `IA32_STAR/LSTAR/CSTAR/FMASK` | Syscall MSRs (managed via MSR lists) |
| `IA32_FS_BASE/GS_BASE` | Segment bases (managed via MSR lists) |

### 3. Control Registers

| Register | Bit | Usage |
|---|---|---|
| CR4 | Bit 13 (VMXE) | Must be 1 before VMXON; set by `relm_enable_vmx_operation()` |
| CR0 | PG, PE, NE, CD, NW | Guest CR0 fixed-bit constraints applied from VMX MSRs |
| CR4 | VMXE, PAE, PSE | Guest CR4 fixed-bit constraints applied from VMX MSRs |

### 4. VMX Instructions

| Instruction | Where Called | Purpose |
|---|---|---|
| `VMXON` | `relm_vmxon()` via IPI | Enter VMX root operation |
| `VMXOFF` | `relm_vmxoff()` via IPI | Exit VMX root operation |
| `VMCLEAR` | `relm_vmclear()` | Init VMCS launch state; detach from CPU |
| `VMPTRLD` | `relm_vmptrld()` | Make VMCS current on this CPU |
| `VMREAD` | `__vmread()` inline | Read a VMCS field |
| `VMWRITE` | `__vmwrite()` inline | Write a VMCS field |
| `VMLAUNCH` | `relm_vmentry_asm()` | First VM-entry on a cleared VMCS |
| `VMRESUME` | `relm_vmentry_asm()` | Subsequent VM-entries on a launched VMCS |

### 5. VMCS Fields

VMCS fields are categorised by function and width. Key fields used by Relm:

**Guest State Area** — saved/restored by hardware on every VM-exit/entry:

```
GUEST_RIP, GUEST_RSP, GUEST_RFLAGS
GUEST_CR0, GUEST_CR3, GUEST_CR4
GUEST_CS/DS/ES/SS/FS/GS: selector, base, limit, AR_bytes
GUEST_GDTR_BASE/LIMIT, GUEST_IDTR_BASE/LIMIT
GUEST_TR, GUEST_LDTR
GUEST_IA32_EFER
GUEST_ACTIVITY_STATE, GUEST_INTERRUPTIBILITY_INFO
```

**Host State Area** — loaded by hardware on VM-exit:

```
HOST_RIP, HOST_RSP
HOST_CR0, HOST_CR3, HOST_CR4
HOST_CS/SS/DS/ES/FS/GS: selector only (bases in separate fields)
HOST_FS_BASE, HOST_GS_BASE
HOST_GDTR_BASE, HOST_IDTR_BASE, HOST_TR_BASE, HOST_TR_SELECTOR
HOST_IA32_EFER
HOST_SYSENTER_CS/ESP/EIP
```

**Control Fields** — configure what causes VM-exits:

```
VMCS_PIN_BASED_EXEC_CONTROLS
VMCS_PRIMARY_PROC_BASED_EXEC_CONTROLS
VMCS_SECONDARY_PROC_BASED_EXEC_CONTROLS
VMCS_ENTRY_CONTROLS
VMCS_EXIT_CONTROLS
EPT_POINTER
VMCS_VPID
VMCS_IO_BITMAP_A, VMCS_IO_BITMAP_B
VMCS_MSR_BITMAP
VMCS_EXCEPTION_BITMAP
CR3_TARGET_COUNT
```

**MSR List Fields:**

```
VMCS_EXIT_MSR_STORE_ADDR / COUNT
VMCS_EXIT_MSR_LOAD_ADDR  / COUNT
VMCS_ENTRY_MSR_LOAD_ADDR / COUNT
```

**Exit Information Fields** — written by hardware on VM-exit:

```
VMCS_EXIT_REASON
VMCS_VM_EXIT_QUALIFICATION
VMCS_GUEST_PHYSICAL_ADDRESS   (EPT violations)
VMCS_INSTRUCTION_ERROR_FIELD  (VMX instruction failures)
```

---

## Execution Controls Configuration

Relm's VCPU execution controls determine which guest activities cause VM-exits. The configured set:

### Pin-Based Controls

| Control | Effect |
|---|---|
| `VMCS_PIN_EXTINT_EXITING` | External interrupts cause VM-exit |
| `VMCS_PIN_NMI_EXITING` | NMIs cause VM-exit |
| `VMCS_PIN_VIRTUAL_NMIS` | Enable virtual NMI support |
| `VMCS_PIN_PREEMPT_TIMER` | VMX preemption timer enabled |
| `VMCS_PIN_POSTED_INTRS` | Posted interrupts enabled |

### Primary Processor-Based Controls

| Control | Effect |
|---|---|
| `VMCS_PROC_HLT_EXITING` | HLT instruction causes VM-exit |
| `VMCS_PROC_CR8_LOAD/STORE_EXITING` | Guest CR8 accesses cause VM-exit |
| `VMCS_PROC_TPR_SHADOW` | Enable virtual APIC TPR shadow |
| `VMCS_PROC_UNCOND_IO_EXITING` | All IO causes VM-exit (overridden by bitmap) |
| `VMCS_PROC_USE_IO_BITMAPS` | IO bitmap controls IO exits |
| `VMCS_PROC_USE_MSR_BITMAPS` | MSR bitmap controls MSR exits |
| `VMCS_PROC_ACTIVATE_SECONDARY` | Enable secondary proc-based controls |

### Secondary Processor-Based Controls

| Control | Effect |
|---|---|
| `VMCS_PROC2_ENABLE_EPT` | Enable Extended Page Tables |
| `VMCS_PROC2_VPID` | Enable VPID (if CPU supports it) |
| `VMCS_PROC2_RDTSCP` | Allow guest RDTSCP without VM-exit |
| `VMCS_PROC2_UNRESTRICTED_GUEST` | Allow real mode / no-paging guest |
| `VMCS_PROC2_ENABLE_VMFUNC` | Enable VM functions |

### VM-Exit Controls

| Control | Effect |
|---|---|
| `VM_EXIT_HOST_ADDR_SPACE_SIZE` | Host is 64-bit after VM-exit |
| `VMCS_EXIT_SAVE/LOAD_IA32_PAT` | Save/restore PAT MSR on exit |
| `VMCS_EXIT_SAVE/LOAD_EFER` | Save/restore EFER on exit |
| `VMCS_EXIT_ACK_INTR_ON_EXIT` | Acknowledge interrupt on VM-exit |

### VM-Entry Controls

| Control | Effect |
|---|---|
| `VM_ENTRY_IA32E_MODE` | Guest enters 64-bit long mode |
| `VMCS_ENTRY_LOAD_GUEST_PAT` | Load guest PAT MSR on entry |
| `VMCS_ENTRY_LOAD_IA32_EFER` | Load guest EFER on entry |
| `VMCS_ENTRY_LOAD_DEBUG` | Load guest DR7 on entry |

All control values are sanitised against the VMX capability MSRs using the fixed-0/fixed-1 formula before being written to the VMCS. This ensures compatibility across different Intel CPU generations that may require different mandatory bits.

---

## Per-CPU State Architecture

Relm maintains two categories of per-CPU state:

### VMX Root State (per physical CPU)

Managed by `struct host_cpu`, stored in `DEFINE_PER_CPU(relm_per_cpu_hcpu)`:

```
Per-CPU variable: relm_per_cpu_hcpu
  Points to: struct host_cpu
    ├── logical_cpu_id    which CPU this is
    ├── vmxon (VA)        4KB VMXON region
    └── vmxon_pa          physical address for VMXON instruction
```

Populated before the VMXON IPI. One `host_cpu` exists per online CPU for the entire lifetime of the module.

### Current VCPU (per physical CPU)

```
Per-CPU variable: current_vcpu
  Points to: struct vcpu (or NULL)
```

Set by the VCPU kthread on its pinned CPU before VMLAUNCH. Read by `relm_vmexit_handler` on every VM-exit to find the VCPU struct without any parameter passing.

### Interaction Between the Two

```
CPU N's per-CPU state:
  relm_per_cpu_hcpu[N] → host_cpu for CPU N  (set once at module_init, never changes)
  current_vcpu[N]      → vcpu pinned to N    (set by kthread, cleared on thread exit)
```

Because Relm currently supports `Relm_MAX_VCPUS=1`, only one CPU (CPU `HOST_CPU_ID=1`) will have `current_vcpu` set during VM execution. All other CPUs have `current_vcpu=NULL` and `relm_per_cpu_hcpu` pointing to their host_cpu structs.

---

## Locking Model

Relm uses a minimal locking strategy:

| Lock | Type | Protects |
|---|---|---|
| `vm->lock` | `spinlock_t` | `vm->state` transitions (RUNNING / STOPPED / INITIALIZED) |
| `vcpu->lock` | `spinlock_t` | Reserved for future use (VCPU state transitions) |
| `hcpu->lock` | `spinlock_t` | Reserved for future use (per-CPU host state) |
| `vmx_enable_work.failed_cpus` | `atomic_t` | Concurrent increment from multiple IPI handlers |

The VCPU loop itself (`relm_vcpu_loop`) holds no locks during the VM-entry loop. The pinning guarantee (single-CPU affinity) means only one thread can be executing VMX instructions for a given VCPU at any time, so no lock is needed to protect VMCS access.

VM-exit handling code (`relm_handle_vmexit` and its callees) runs with IRQs enabled (the CPU re-enables interrupts as part of VM-exit). Handlers must not take sleeping locks unless they explicitly handle the sleeping/waking state machine.

---

## Scalability Constraints and Extension Points

The current implementation has the following hard limits and extension paths:

| Parameter | Current Value | Extension Path |
|---|---|---|
| `Relm_MAX_VCPUS` | 1 | Increase constant; assign unique `target_cpu_id` per VCPU in `relm_vm_add_vcpu` |
| `HOST_CPU_ID` | 1 | Replace with dynamic assignment: VCPU 0 → CPU 1, VCPU 1 → CPU 2, etc. |
| Guest RAM start GPA | Always `0x0` | Add GPA start parameter to `relm_vm_allocate_guest_ram` callers |
| Guest page tables | 1 GB identity map | Extend PD/PDPT structure for larger guests; add PDPTE for >1 GB |
| MMIO regions | Not implemented | Add `relm_vm_map_mmio_region`; implement EPT violation dispatch for MMIO ranges |
| Multiple VMs | Not implemented | `relm_create_vm` already accepts `vm_id`; add a VM registry and `relm_get_vm` lookup |
| `Relm_MAX_MANAGED_MSRS` | 8 | Increase constant; no structural changes needed |

---

## Interaction With Other Documents

| Document | Relationship |
|---|---|
| `memory_model.md` | Details the internal layout and allocation of every memory structure described in this document |
| `vcpu_execution_model.md` | Details the step-by-step execution inside `relm_vcpu_loop`, including the two-phase init and VM-entry loop |
