# Relm Hypervisor VCPU Execution Model

---

## Overview

This document explains how a VCPU is created, initialised, pinned to a physical CPU, and driven through the VM-entry/VM-exit loop in Relm. It covers:

- Why VCPU initialisation is split into two phases
- The CPU affinity problem and why it is fundamental, not incidental
- The exact sequence of steps inside `relm_vcpu_loop` and the hardware reason each step exists
- What happens on every VM-exit and how the loop resumes
- The cleanup contract and why it must be respected

If you have read `architecture.md` you already know the high-level shape of the system. This document zooms into the per-VCPU execution path and explains the **why** behind every ordering decision.

---

## Background: The VMCS CPU-Locality Constraint

Every design decision in this document traces back to one hardware rule stated in Intel SDM Vol 3C 24.1:

> A logical processor may maintain a number of VMCSs that are active.
> A single one of these — the **current VMCS** — is used by VMREAD,
> VMWRITE, VMLAUNCH, VMRESUME, and VMCLEAR.

The processor tracks the current VMCS using an **internal per-CPU register** called the VMCS pointer. This register is not memory-mapped and cannot be read by software. The only way to set it is with the `VMPTRLD` instruction, which takes the physical address of a VMCS region as its operand and atomically makes that VMCS current on the executing logical CPU.

The consequence is direct: **a VMCS is not portable**. Once `VMPTRLD` runs on CPU N, all subsequent `VMREAD`, `VMWRITE`, `VMLAUNCH`, and `VMRESUME` instructions must also run on CPU N. If the thread executing those instructions migrates to CPU M, the VMCS is still current on CPU N's internal register. CPU M has no current VMCS. Any VMX instruction on CPU M will fail immediately with `VMfailInvalid` (CF=1), which means *there is no valid current VMCS on this CPU*.

This is not a software bug that can be worked around. It is a hardware architectural constraint. The entire VCPU threading model in Relm exists to satisfy it.

---

## Two-Phase Initialisation

The VCPU lifecycle is split into two phases to resolve a conflict between two incompatible constraints:

| Constraint | Implication |
|---|---|
| Intel VMX: all VMCS operations must run on the same logical CPU | No VMCS work until the thread is pinned |
| Linux kernel: `GFP_KERNEL` memory allocation may sleep | Allocation cannot happen from atomic/IPI context |

Because VMX IPI handlers (which enable VMX root mode via `VMXON` across all CPUs) run with interrupts disabled and cannot sleep, and because VMCS operations require a pinned thread that has not yet been created at allocation time, the only safe solution is to separate the two concerns into distinct phases.

### Phase 1 — Memory Allocation (`relm_vcpu_alloc_init`)

**When:** Called from `relm_vm_add_vcpu`, which runs in sleepable module context.  
**Context:** Any sleepable kernel context. `GFP_KERNEL` allowed.  
**VMX instructions executed:** None.

Phase 1 allocates and initialises all per-VCPU memory:

```
vcpu struct            kzalloc()
host stack (16 KB)     __get_free_pages(GFP_KERNEL | __GFP_ZERO, ORDER=2)
VMCS region            __get_free_pages() + write revision ID (plain memory write)
IO bitmap (8 KB)       __get_free_pages() + memset(0)
MSR bitmap (4 KB)      __get_free_page() + set intercept bits
MSR load/store areas   alloc_pages() + populate index/value tables
```

The VMCS revision ID is written into the first 4 bytes of the VMCS region as a plain `*(uint32_t *)vmcs = _vmcs_revision_id()`. This is a memory write, not a VMX instruction. It is required to match the value in `MSR_IA32_VMX_BASIC[30:0]` before `VMCLEAR` is executed, but the write itself is safe anywhere.

Physical addresses of all allocated structures are computed with `virt_to_phys()` and stored in the `vcpu` struct (`vmcs_pa`, `io_bitmap_pa`, `msr_bitmap_pa`, `vmexit_store_pa`, etc.) for later use by Phase 2.

After Phase 1, the `vcpu` struct is fully populated and all backing memory is ready. No VMX instruction has touched any of it.

### Phase 2 — VMCS Structural Setup (`relm_vcpu_vmcs_setup`)

**When:** Called from inside the VCPU kthread, after the thread has been pinned to its target CPU.  
**Context:** Kthread context on the pinned CPU.  
**VMX instructions executed:** VMCLEAR, VMPTRLD, and multiple VMWRITEs.

Phase 2 executes the VMX instruction sequence that activates the VMCS on the pinned CPU and writes all structural configuration fields. The ordering within Phase 2 is also strictly prescribed and is explained in the [Step-by-Step Execution Order](#step-by-step-execution-order) section below.

---

## CPU Affinity and Thread Pinning

### The Problem

When Linux creates a kthread with `kthread_create()`, the scheduler places it on any available CPU according to its load-balancing algorithm. The thread may start on CPU 0, then be migrated to CPU 2 between two consecutive instructions. For a normal kthread this is invisible and harmless. For a VCPU thread that must execute `VMPTRLD` and `VMLAUNCH` on the same CPU, it is fatal.

### The Solution: Self-Pinning from Inside the Thread

Relm pins the VCPU kthread to its target CPU from **inside the kthread itself**, using `relm_vcpu_pin_to_cpu()`. This function must be called as `current` (i.e. from within the thread being pinned), because:

1. `set_cpus_allowed_ptr(current, mask)` updates the running task's CPU affinity mask. If the new mask excludes the current CPU, the scheduler sets `TIF_NEED_RESCHED` and will migrate the task at the next preemption point.
2. `schedule()` is called immediately after to trigger that preemption point voluntarily, causing migration to happen now rather than at some future arbitrary point.
3. A `while (smp_processor_id() != target_cpu_id)` busy-wait loop confirms the migration happened before returning.

```c
int relm_vcpu_pin_to_cpu(struct vcpu *vcpu, int target_cpu_id)
{
    cpumask_t new_mask;
    cpumask_clear(&new_mask);
    cpumask_set_cpu(target_cpu_id, &new_mask);

    // Restrict this task to exactly one CPU.
    // If we are not currently on target_cpu_id, the scheduler will
    // migrate us at the next preemption point.
    set_cpus_allowed_ptr(vcpu->host_task, &new_mask);

    // Voluntarily yield to trigger migration now.
    schedule();

    // Confirm we are on the right CPU. Retry if not.
    while (smp_processor_id() != target_cpu_id)
        schedule();

    // After this point: affinity = {target_cpu_id}.
    // The scheduler will never migrate this thread again.
    return 0;
}
```

After `relm_vcpu_pin_to_cpu()` returns, the thread's CPU affinity mask is `{target_cpu_id}` — a set of exactly one CPU. **The scheduler cannot migrate this thread to any other CPU** for the remainder of its execution. This guarantee is what makes all subsequent VMX operations safe.

### Why Not `kthread_bind()`?

`kthread_bind()` pins a thread to a CPU *before* it is started (`wake_up_process()` has not been called yet). This would work in principle but loses two important capabilities:

1. The thread cannot do any pre-pin work (like the first `relm_set_current_vcpu()` call described below).
2. The thread cannot report its own pinning status or handle pinning failures in context.

Self-pinning from inside the thread is more flexible and allows the thread to be the authoritative actor for its own CPU locality.

### The `current_vcpu` Per-CPU Pointer

The vmexit handler (`relm_vmexit_handler`) runs on VM-exit. At that point, the CPU has jumped to the host RIP and the host RSP has been restored, but there is no parameter passing. The handler has no arguments. It needs to find the `vcpu` struct for the CPU it is running on.

Relm solves this with a `DEFINE_PER_CPU` pointer:

```c
DEFINE_PER_CPU(struct vcpu *, current_vcpu);
```

`DEFINE_PER_CPU` creates one independent storage slot per physical CPU in a dedicated kernel section. Writing `this_cpu_write(current_vcpu, vcpu)` on CPU 0 writes to CPU 0's slot only. After migration to CPU 1, `this_cpu_read(current_vcpu)` reads CPU 1's slot, which is a completely separate memory location.

This means the pointer must be set **twice** — once on the starting CPU (before migration) and once on the target CPU (after migration):

```
[starting CPU]  relm_set_current_vcpu(vcpu)  ← slot on starting CPU populated
    |
    ↓  migrate
    |
[target CPU]    relm_set_current_vcpu(vcpu)  ← slot on target CPU populated
```

Setting it only once after migration would leave the starting CPU's slot stale. Setting it only before migration would leave the target CPU's slot null. Both calls are necessary.

---

## Step-by-Step Execution Order

The following is the full annotated sequence inside `relm_vcpu_loop`. Each step includes what it does, what hardware constraint it satisfies, and what would break if it were skipped or reordered.

---

### Step 1 — Register on Starting CPU

```c
relm_set_current_vcpu(vcpu);
```

**What it does:** Writes the `vcpu` pointer into the `current_vcpu` per-CPU slot for the CPU the thread is currently on.

**Why it comes first:** Between `wake_up_process()` and successful migration, the thread is alive and running but not yet on its target CPU. If any event caused a VM-exit during this window (not possible before VMLAUNCH, but architecturally considered), the handler on the starting CPU would need to find the vcpu. Setting the pointer here eliminates any null-pointer window on the starting CPU.

**If skipped:** No immediate failure (VMLAUNCH has not happened yet), but the starting CPU's `current_vcpu` slot is left pointing at whatever was there before (likely NULL or a stale pointer from a previous VCPU). Defensive practice.

---

### Step 2 — Pin to Target CPU

```c
ret = relm_vcpu_pin_to_cpu(vcpu, vcpu->target_cpu_id);
```

**What it does:** Sets CPU affinity to `{target_cpu_id}` and blocks until physical migration is confirmed. After this returns, `smp_processor_id() == vcpu->target_cpu_id` is guaranteed and will remain true for the lifetime of the thread.

**Why it must happen before any VMCS work:** `VMCLEAR`, `VMPTRLD`, `VMWRITE`, `VMLAUNCH`, and `VMRESUME` must all execute on the same logical CPU. Pinning here creates that guarantee for everything that follows.

**If skipped:** The thread would proceed with VMCS setup on whatever CPU it happens to be on. The scheduler could migrate it between `VMPTRLD` and `VMLAUNCH`. `VMLAUNCH` would then fail with `VMfailInvalid` (CF=1) because the VMCS is not current on the new CPU.

---

### Step 3 — Re-register on Target CPU

```c
relm_set_current_vcpu(vcpu);
```

**What it does:** Writes the `vcpu` pointer into the `current_vcpu` per-CPU slot for the target CPU.

**Why it must happen after Step 2:** The per-CPU slot on the target CPU was empty (or stale). After VMLAUNCH, every VM-exit will land on this CPU and the handler will call `relm_get_current_vcpu()` on this CPU. The pointer must be set before VMLAUNCH.

**If skipped:** The vmexit handler reads a null or stale pointer from the target CPU's `current_vcpu` slot, causing a null pointer dereference or wrong-VCPU dispatch on the first VM-exit.

---

### Step 4 — Phase 2 VMCS Setup

```c
ret = relm_vcpu_vmcs_setup(vcpu);
```

This call executes a sequence of VMX instructions in a mandatory order. Each sub-step is described below.

#### 4a — VMCLEAR

```
VMCLEAR(vmcs_pa)
```

Initialises the VMCS region for use on this CPU. The hardware sets the VMCS **launch state** to `clear`. This is distinct from zeroing the memory (which happened in Phase 1 with `__GFP_ZERO`); the hardware launch state is tracked internally and is only set correctly by `VMCLEAR`.

The launch state controls which VM-entry instruction is valid:
- `clear` state → only `VMLAUNCH` is valid
- `launched` state (set after first successful `VMLAUNCH`) → only `VMRESUME` is valid

Using `VMRESUME` on a clear-state VMCS generates `VMfailValid` (ZF=1). Using `VMLAUNCH` on a launched-state VMCS generates `VMfailValid`. `VMCLEAR` establishes the correct starting state.

`VMCLEAR` also detaches the VMCS from any CPU it may have been active on. In Relm's design the VMCS is freshly allocated in Phase 1 so it has never been active, but `VMCLEAR` is required as the first VMX operation on any VMCS regardless.

**Must come before VMPTRLD.** The SDM states that VMPTRLD on a VMCS that has not been VMCLEARed has undefined behaviour.

#### 4b — VMPTRLD

```
VMPTRLD(vmcs_pa)
```

Makes the VMCS current on this CPU. After this instruction:
- The CPU's internal VMCS pointer register is set to `vmcs_pa`
- `VMREAD` and `VMWRITE` implicitly operate on this VMCS
- `VMLAUNCH` and `VMRESUME` will use this VMCS
- **The thread must not migrate to another CPU**

`VMPTRLD` is the point of no return for CPU locality. Every subsequent VMX instruction in this thread is now committed to the pinned CPU.

**Must come after VMCLEAR.** Must come before any VMWRITE.

#### 4c — EPT Pointer

```c
CHECK_VMWRITE(EPT_POINTER, vcpu->vm->ept->eptp);
```

Writes the Extended Page Table Pointer (EPTP) into the VMCS. The EPTP is the physical address of the EPT PML4 table, plus configuration bits (memory type, page-walk length, dirty/access tracking flags).

The EPT is the second level of address translation used in hardware-assisted virtualisation:

```
Guest Virtual Address
        ↓  (guest page tables, walked by CPU)
Guest Physical Address (GPA)
        ↓  (EPT, walked by CPU using EPTP)
Host Physical Address (HPA)
```

Without the EPT pointer, every guest memory access causes an EPT violation VM-exit. Writing the EPTP here enables hardware-accelerated memory translation for all guest accesses.

The EPTP value was computed during `relm_create_vm()` → `relm_setup_ept()` and stored in `vm->ept->eptp`. It is written first among the structural VMCS fields because it establishes the fundamental substrate that all guest execution depends on.

#### 4d — Execution Controls

```c
relm_apply_exec_controls(vcpu);
```

Writes four VMCS control fields: pin-based, primary processor-based, secondary processor-based, and VM-exit/VM-entry controls. Each field is sanitised against the VMX capability MSRs using the fixed-0/fixed-1 formula:

```c
final = (desired | fixed0) & (desired | fixed1)
// fixed0 bits: CPU requires these to be 1
// fixed1 bits: CPU permits these to be 1
```

This ensures no reserved bit is set and no required bit is cleared. The result is the maximum set of desired features that the hardware will accept.

Execution controls must be written before the bitmap fields because the bitmap PA fields are only meaningful when the corresponding control bits (e.g. `VMCS_PROC_USE_IO_BITMAPS`, `VMCS_PROC_USE_MSR_BITMAPS`) are set. Writing controls first makes the VMCS internally consistent at each step.

#### 4e — VPID

```c
CHECK_VMWRITE(VMCS_VPID, vcpu->vpid);
```

The Virtual Processor Identifier (VPID) is a 16-bit tag that the CPU attaches to TLB entries belonging to this VCPU. Without VPID, every VM-exit and VM-entry requires a full TLB flush, because the host and guest share the same TLB address space. With VPID, the CPU keeps host TLB entries (tagged VPID=0) and guest TLB entries (tagged with this VCPU's VPID) simultaneously. VM-exits only invalidate guest entries for this VPID, not the entire TLB.

VPID=0 is reserved for VMX root mode (the host). Guest VPIDs start at 1, matching Relm's 1-based VPID numbering.

#### 4f — IO Bitmap Physical Addresses

```c
_vmwrite(VMCS_IO_BITMAP_A, vcpu->io_bitmap_pa);
_vmwrite(VMCS_IO_BITMAP_B, vcpu->io_bitmap_pa + VMCS_IO_BITMAP_SIZE);
```

The IO bitmap is an 8 KB region (two contiguous 4 KB pages) where each bit represents one IO port (0x0000–0xFFFF). A set bit causes a VM-exit when the guest executes `IN` or `OUT` for that port. A clear bit allows the access without a VM-exit.

- Bitmap A: ports 0x0000–0x7FFF (first 4 KB page)
- Bitmap B: ports 0x8000–0xFFFF (second 4 KB page, at `io_bitmap_pa + 4096`)

The bitmaps were zeroed in Phase 1 (all accesses pass through without VM-exit). The PA was stored in `vcpu->io_bitmap_pa`. This step registers those PAs with the VMCS so the CPU knows where to look.

#### 4g — MSR Bitmap Physical Address

```c
_vmwrite(VMCS_MSR_BITMAP, vcpu->msr_bitmap_pa);
```

Similar to the IO bitmap. One 4 KB page where each bit represents an MSR index. A set bit causes a VM-exit when the guest accesses that MSR via `RDMSR` or `WRMSR`. This allows the hypervisor to emulate or intercept specific MSRs while allowing common ones (EFER, STAR, LSTAR, etc.) to pass through via the MSR load/store lists (see below).

#### 4h — MSR Load/Store Area Physical Addresses and Counts

```c
_vmwrite(VMCS_EXIT_MSR_STORE_ADDR,  vcpu->vmexit_store_pa);
_vmwrite(VMCS_EXIT_MSR_STORE_COUNT, vmexit_count);
_vmwrite(VMCS_EXIT_MSR_LOAD_ADDR,   vcpu->vmexit_load_pa);
_vmwrite(VMCS_EXIT_MSR_LOAD_COUNT,  vmentry_count);
_vmwrite(VMCS_ENTRY_MSR_LOAD_ADDR,  vcpu->vmentry_load_pa);
_vmwrite(VMCS_ENTRY_MSR_LOAD_COUNT, vmentry_count);
```

These six fields point the CPU at three arrays of `{ index, reserved, value }` entries. On every VM-exit and VM-entry, the CPU automatically reads and writes these arrays to swap MSR values between guest and host, without any software RDMSR/WRMSR calls in the vmexit handler.

The three lists serve different purposes:

| List | Direction | Purpose |
|---|---|---|
| `vmexit_store_area` | CPU → memory on VM-exit | Save guest's current MSR values (EFER, LSTAR, FS_BASE, etc.) |
| `vmexit_load_area` | Memory → CPU on VM-exit | Restore host's MSR values so host code runs with correct EFER, GS_BASE, etc. |
| `vmentry_load_area` | Memory → CPU on VM-entry | Load guest's MSR values so the guest runs with its own EFER, LSTAR, etc. |

Without these lists, the vmexit handler would need to call `RDMSR`/`WRMSR` for every managed MSR on every exit — potentially 7 MSRs × 2 operations × every exit. The hardware lists eliminate this cost entirely.

#### 4i — Exception Bitmap

```c
CHECK_VMWRITE(VMCS_EXCEPTION_BITMAP,
              vcpu->exception_bitmap & 0xFFFFFFFF);
```

A 32-bit field where bit N, when set, causes a VM-exit when the guest takes exception vector N. Relm sets:
- Bit 6 (`#UD`, Invalid Opcode): intercept to emulate unsupported instructions
- Bit 14 (`#PF`, Page Fault): intercept for shadow paging or memory fault debugging

The bitmap value was set in Phase 1 in the `vcpu` struct. This step writes it to the VMCS.

#### 4j — CR3 Target Count = 0

```c
CHECK_VMWRITE(CR3_TARGET_COUNT, 0ULL);
```

When a guest executes `MOV CR3, rax` (loading a new page table root), the CPU normally causes a VM-exit so the hypervisor can track page table switches. The CR3 target list is a hardware optimisation: if the new CR3 value matches one of up to 4 entries in the target list, the `MOV CR3` does **not** cause a VM-exit. Count=0 means the list is empty and all guest CR3 writes cause VM-exits. This is the safest default.

---

### Step 5 — Host and Guest Register State (`relm_init_vmcs_state`)

```c
ret = relm_init_vmcs_state(vcpu);
```

This call writes the VMCS `HOST_*` and `GUEST_*` fields that describe the register state the CPU will save/restore on VM-exit and VM-entry.

**Host state** fields tell the CPU what register values to restore when a VM-exit occurs and control transfers to the host. These values must be read from the **live CPU state** on the pinned CPU, because they are per-CPU structures:

| VMCS Field | Source | Why CPU-local |
|---|---|---|
| `HOST_GDTR_BASE` | `sgdt` instruction | GDT is per-CPU on Linux |
| `HOST_IDTR_BASE` | `sidt` instruction | IDT is per-CPU on Linux |
| `HOST_TR_BASE` | `str` + GDT walk | TSS is per-CPU on Linux |
| `HOST_TR_SELECTOR` | `str` instruction | Per-CPU TSS selector |
| `HOST_FS_BASE` | `RDMSR(MSR_FS_BASE)` | FS_BASE is per-CPU (used for `current` pointer) |
| `HOST_GS_BASE` | `RDMSR(MSR_GS_BASE)` | GS_BASE is per-CPU |
| `HOST_CR0/CR3/CR4` | `mov rX, crN` | Live CPU register state |
| `HOST_IA32_EFER` | `RDMSR(MSR_EFER)` | EFER is per-CPU |
| `HOST_SYSENTER_*` | `RDMSR(MSR_IA32_SYSENTER_*)` | Per-CPU syscall setup |

If any of these were read on a different CPU and the guest VM-exits on the pinned CPU, the CPU would restore wrong GDT/IDT/TR/GS_BASE values into the host registers. On a homogeneous SMP system the values might accidentally be the same, but on any system with per-CPU asymmetry (NUMA, hotplug, heterogeneous CPUs) this would corrupt host state and crash.

`HOST_RIP` is set to `relm_vmexit_handler` — the address of the assembly stub that saves guest GPRs and dispatches exit reasons. `HOST_RSP` is set to `vcpu->host_rsp`, the pre-computed top-of-stack value from Phase 1.

**Guest state** fields describe the initial architectural state the guest will start in: RIP=0x0 (entry point of guest code), RSP=top of guest RAM, RFLAGS=0x2 (reserved bit 1 must be 1), flat segment descriptors, and CR3 pointing at the guest PML4 created during `relm_vm_create_guest_page_tables()`.

This step **must come after** `relm_vcpu_vmcs_setup()` because the VMCS must be current (post-VMPTRLD) for any VMWRITE to succeed, and it **must come on the pinned CPU** for the reasons above.

---

### Step 6 — VM-Entry Loop

```c
while (!kthread_should_stop()) {
    ret = relm_vmentry_asm(&vcpu->regs, vcpu->launched);
    if (ret != 0) { /* VMX instruction error, break */ }
    if (!vcpu->launched) vcpu->launched = 1;
}
```

`relm_vmentry_asm` is an assembly function with two responsibilities depending on `launched`:

- `launched == 0` → executes `VMLAUNCH`. The CPU transitions to guest mode for the first time. The hardware sets the VMCS internal launch state to `launched`.
- `launched == 1` → executes `VMRESUME`. The CPU transitions to guest mode using the saved guest state from the previous VM-exit.

#### What Happens on VM-Exit

When the guest hits a VM-exit condition (exception matching the bitmap, MSR access, HLT, CPUID, IO port access, EPT violation, etc.), the CPU performs the following atomically in hardware:

1. Saves all guest register state into the VMCS (`GUEST_RIP`, `GUEST_RSP`, `GUEST_RFLAGS`, `GUEST_CR0–4`, segment bases, etc.)
2. Saves guest MSRs listed in `vmexit_store_area` to memory
3. Loads host MSRs from `vmexit_load_area` from memory
4. Restores host CR0, CR3, CR4, segment registers from VMCS `HOST_*` fields
5. Sets RSP to `HOST_RSP` (= `vcpu->host_rsp`)
6. Jumps to `HOST_RIP` (= `relm_vmexit_handler`)

Note that general-purpose registers (RAX, RBX, RCX, RDX, RSI, RDI, RBP, R8–R15) are **not** saved by hardware. The vmexit handler assembly stub must save them manually before calling any C code, and restore them before `VMRESUME`.

#### What `relm_vmentry_asm` Returns

- **Returns 0:** A VM-exit occurred and was handled by `relm_vmexit_handler`. The handler updated `vcpu->regs` with the guest register values. The loop iterates and calls `VMRESUME`.
- **Returns non-zero:** `VMLAUNCH` or `VMRESUME` itself failed — the instruction never transferred to the guest. This indicates a VMCS configuration error (invalid guest state, unsupported control bit combination, etc.). The error code is readable from `VMCS_INSTRUCTION_ERROR_FIELD` via `__vmread`.

#### The `launched` Flag

After the first successful `VMLAUNCH`, `vcpu->launched` is set to 1. From that point on, every iteration uses `VMRESUME`. Using `VMLAUNCH` again on an already-launched VMCS would generate `VMfailValid` (ZF=1). The flag is reset to 0 in `relm_run_vcpu()` before starting the kthread, so each time a VCPU thread starts fresh it uses `VMLAUNCH` for its first entry.

---

### Step 7 — Cleanup

```c
_out_vmclear:
    relm_vmclear(vcpu);

_out_clear_vcpu:
    relm_set_current_vcpu(NULL);
```

#### Why VMCLEAR in Cleanup

After the loop exits, the VMCS is still "active and current" on the pinned CPU — the CPU's internal VMCS pointer register still holds `vmcs_pa`. When `module_exit` runs `relm_vmx_disable_on_all_cpus()` and executes `VMXOFF` on every CPU, the Intel SDM requires:

> If there is a current VMCS on the logical processor that executes VMXOFF, that VMCS is made inactive and is no longer current.

More critically: if a VMCS that was active on a CPU is not VMCLEARed before VMXOFF, the hardware may not flush its internal VMCS cache to memory. Subsequent attempts to use that VMCS on another CPU (e.g. after module reload) could see stale data. VMCLEAR in the cleanup path ensures:

1. The VMCS is detached from the CPU (no longer current or active)
2. All hardware-cached VMCS fields are flushed to the VMCS memory region
3. VMXOFF on this CPU will complete cleanly

`VMCLEAR` runs on the pinned CPU, which is correct — it must run on the CPU where the VMCS is active.

#### Why `relm_set_current_vcpu(NULL)` Last

After `VMCLEAR`, the VMCS is gone from this CPU's perspective. Any VM-exit after this point is impossible (no active VMCS). Setting `current_vcpu` to NULL prevents the vmexit handler from seeing a dangling pointer to a VCPU that may be freed shortly by `relm_free_vcpu()` in the VM teardown path.

---

## Complete Sequence Diagram

```
[module_init / relm_vm_add_vcpu]       [IPI on all CPUs]
     |                                       |
     | kzalloc(host_cpu)                     |
     | setup_vmxon_region()                  |
     | per_cpu(hcpu) = hcpu                  |
     |                    on_each_cpu ───────┤
     |                                  CR4.VMXE = 1
     |                                  IA32_FEATURE_CONTROL
     |                                  VMXON(vmxon_pa)
     |                                  [CPU in VMX root mode]
     |
     | relm_vcpu_alloc_init()   [Phase 1: GFP_KERNEL, no VMX]
     |   kzalloc vcpu struct
     |   __get_free_pages host_stack
     |   __get_free_pages VMCS + write revision ID
     |   __get_free_pages IO bitmap + memset 0
     |   __get_free_page  MSR bitmap + set bits
     |   alloc_pages MSR areas x3 + populate
     |   [all memory ready, vcpu->*_pa set]
     |
     | kthread_create(relm_vcpu_loop)
     | wake_up_process()
     |
     ↓
[kthread starts on scheduler-chosen CPU]
     |
     | relm_set_current_vcpu(vcpu)        ← current_vcpu[starting_cpu] = vcpu
     |
     | relm_vcpu_pin_to_cpu(target_cpu)
     |   set_cpus_allowed_ptr({target})
     |   schedule()  ──── migrate ────────────────────────────────────┐
     |   while(cpu != target) schedule()                              ↓
     |                                            [now on target_cpu, pinned]
     |
     | relm_set_current_vcpu(vcpu)        ← current_vcpu[target_cpu] = vcpu
     |
     | relm_vcpu_vmcs_setup()             [Phase 2: VMX on pinned CPU]
     |   VMCLEAR(vmcs_pa)                 ← launch state = clear
     |   VMPTRLD(vmcs_pa)                 ← VMCS current on this CPU
     |   VMWRITE EPT_POINTER              ← GPA → HPA translation enabled
     |   VMWRITE exec controls            ← VM-exit triggers configured
     |   VMWRITE VPID                     ← TLB tagged for this VCPU
     |   VMWRITE IO_BITMAP_A/B            ← IO port intercepts registered
     |   VMWRITE MSR_BITMAP               ← MSR intercepts registered
     |   VMWRITE MSR area PAs/counts      ← automatic MSR swap registered
     |   VMWRITE EXCEPTION_BITMAP         ← exception intercepts registered
     |   VMWRITE CR3_TARGET_COUNT = 0     ← all CR3 writes intercepted
     |
     | relm_init_vmcs_state()             [live CPU state → VMCS]
     |   sgdt → HOST_GDTR_BASE
     |   sidt → HOST_IDTR_BASE
     |   str  → HOST_TR_BASE/SELECTOR
     |   rdmsr FS/GS/EFER/SYSENTER → HOST_FS_BASE etc.
     |   mov cr0/3/4 → HOST_CR0/CR3/CR4
     |   HOST_RSP = vcpu->host_rsp
     |   HOST_RIP = relm_vmexit_handler
     |   vcpu->regs.rip/rsp → GUEST_RIP/RSP
     |   [all VMCS fields populated]
     |
     | ┌─────────────────────────────────────────────────┐
     | │  VM-entry loop                                  │
     | │                                                 │
     | │  relm_vmentry_asm(&regs, launched=0)            │
     | │      VMLAUNCH ──── guest runs ────┐             │
     | │                                  │ VM-exit     │
     | │                                  ↓             │
     | │                         HOST_RSP restored      │
     | │                         HOST_RIP executed      │
     | │                         relm_vmexit_handler()  │
     | │                           save guest GPRs      │
     | │                           dispatch exit reason │
     | │                           update vcpu->regs    │
     | │                           return to asm stub   │
     | │      ← returns 0                               │
     | │  vcpu->launched = 1                            │
     | │                                                 │
     | │  relm_vmentry_asm(&regs, launched=1)            │
     | │      VMRESUME ─── guest runs ─────┐             │
     | │                         (repeat)  │             │
     | └─────────────────────────────────────────────────┘
     |
     | [kthread_should_stop() or VMX error]
     |
     | VMCLEAR(vmcs_pa)                   ← detach VMCS from this CPU
     | relm_set_current_vcpu(NULL)        ← clear dangling pointer
     | return
```

---

## Error Handling

### VMX Instruction Failures

Every VMX instruction (`VMXON`, `VMCLEAR`, `VMPTRLD`, `VMWRITE`, `VMLAUNCH`, `VMRESUME`) sets RFLAGS to indicate success or failure:

| Condition | RFLAGS | Meaning |
|---|---|---|
| Success | CF=0, ZF=0 | Instruction completed normally |
| `VMfailInvalid` | CF=1 | No current VMCS (VMPTRLD not done, or wrong CPU) |
| `VMfailValid` | ZF=1 | Current VMCS exists but instruction failed; read `VMCS_INSTRUCTION_ERROR_FIELD` |

Relm checks both CF and ZF after every VMX instruction using `pushfq` + `popq` to capture RFLAGS atomically.

### VMLAUNCH/VMRESUME Failures

If `relm_vmentry_asm` returns non-zero, the VM-entry instruction itself failed (the guest never ran). Relm reads `VMCS_INSTRUCTION_ERROR_FIELD` and logs the guest state (RIP, RSP, RFLAGS, CR0–4) via `relm_dump_vcpu()` for diagnosis. Common causes are:

- Invalid guest segment access rights (AR bytes)
- EFER/CR0/CR4 combination inconsistent with VM-entry controls (e.g. `VM_ENTRY_IA32E_MODE` set but guest EFER.LMA=0)
- EPT pointer not set or set to a physically invalid address
- Host RSP not 16-byte aligned

### Pinning Failure

If `relm_vcpu_pin_to_cpu` fails (target CPU offline or not possible), the thread sets `vcpu->state = VCPU_STATE_ERROR` and returns without executing any VMX instructions. The VCPU can be freed cleanly because no VMCS is active.

---

## Interaction With Other Documents

| Document | Relationship |
|---|---|
| `architecture.md` | Describes the overall system structure. This document explains the per-VCPU execution detail within that structure. |
| `memory_model.md` | Describes EPT construction and guest memory layout. This document describes how the EPTP from that system is registered with the VMCS in Step 4c. |
| `vmexit_dispatch.md` *(if exists)* | Describes what happens inside `relm_vmexit_handler`. This document describes the mechanism that calls it (VMLAUNCH/VMRESUME) and how control returns. |

---

## Glossary

| Term | Definition |
|---|---|
| **VMCS** | Virtual Machine Control Structure. A hardware-managed data structure that holds all state for one VCPU's guest/host configuration. |
| **VMCS pointer** | An internal per-CPU CPU register that holds the physical address of the current VMCS. Set by `VMPTRLD`. |
| **VMPTRLD** | VMX instruction that makes a VMCS current on the executing CPU. |
| **VMCLEAR** | VMX instruction that flushes a VMCS to memory and sets its launch state to clear. |
| **VMLAUNCH** | VMX instruction that enters guest mode for the first time on a cleared VMCS. |
| **VMRESUME** | VMX instruction that re-enters guest mode on a launched VMCS. |
| **VMfailInvalid** | VMX instruction failure mode (CF=1) indicating no current VMCS exists on this CPU. |
| **VMfailValid** | VMX instruction failure mode (ZF=1) indicating a current VMCS exists but the instruction failed. |
| **EPT** | Extended Page Tables. Intel hardware mechanism for translating guest-physical addresses to host-physical addresses. |
| **EPTP** | Extended Page Table Pointer. Physical address of the EPT PML4, written to the VMCS. |
| **VPID** | Virtual Processor Identifier. 16-bit tag applied to TLB entries to allow host and guest TLB entries to coexist. |
| **VM-exit** | Transition from guest mode to host mode, triggered by a configured condition. |
| **VM-entry** | Transition from host mode to guest mode, via VMLAUNCH or VMRESUME. |
| **CPU affinity** | The set of logical CPUs a kernel thread is permitted to run on. Set via `set_cpus_allowed_ptr()`. |
| **per-CPU variable** | A kernel construct (`DEFINE_PER_CPU`) that allocates one independent copy of a variable per logical CPU. |
| **Phase 1** | Memory-only VCPU initialisation. No VMX instructions. Safe from any sleepable context. |
| **Phase 2** | VMCS structural initialisation. All VMX instructions. Must run on pinned CPU. |
