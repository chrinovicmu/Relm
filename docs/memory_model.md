# Relm Hypervisor Memory Model

---

## Overview

This document describes every memory structure that Relm allocates, how those structures relate to each other, and how the hardware uses them at runtime. It covers:

- The two-level address translation model (GVA → GPA → HPA)
- Guest physical memory: allocation, EPT mapping, and layout
- Guest page table construction and identity mapping
- VMCS region: format and lifecycle
- VCPU host stack: layout and alignment requirements
- IO bitmap: structure and port intercept mechanism
- MSR bitmap: structure and intercept mechanism
- MSR load/store areas: automatic register swap on VM-exit/entry
- Per-CPU VMXON regions

---

## Address Translation: Two Levels

When Intel VMX with EPT is enabled, every guest memory access goes through two independent levels of address translation performed entirely in hardware:

```
Guest Virtual Address (GVA)
        │
        │  Level 1: Guest page tables
        │  Walked by the CPU's MMU using the guest CR3 value.
        │  Guest software controls these tables; they live in guest memory.
        │
        ▼
Guest Physical Address (GPA)
        │
        │  Level 2: Extended Page Tables (EPT)
        │  Walked by the CPU's EPT hardware using the EPTP from the VMCS.
        │  Host (hypervisor) controls these tables; they live in host memory.
        │
        ▼
Host Physical Address (HPA)
        │
        ▼
DRAM
```

Neither level is aware of the other. The guest constructs its own page tables using GPAs as if they were physical addresses. The hypervisor maps those GPAs to HPAs through the EPT. The CPU performs both walks on every TLB miss, combining the results to produce the final HPA.

This separation is the foundation of memory isolation: the guest cannot escape its GPA range because any GPA not mapped in the EPT produces an EPT violation VM-exit, which the hypervisor handles.

---

## Guest Physical Memory

### Allocation

Guest RAM is allocated during `relm_create_vm()` via `relm_vm_allocate_guest_ram()`. The entire guest RAM request is satisfied with individual 4 KB host pages allocated with `alloc_page(GFP_KERNEL | __GFP_ZERO)`:

```c
for (i = 0; i < num_pages; i++) {
    page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    region->pages[i] = page;
    gpa = gpa_start + (i * PAGE_SIZE);
    hpa = PFN_PHYS(page_to_pfn(page));
    relm_ept_map_page(vm->ept, gpa, hpa, EPT_RWX);
}
```

Each page is individually tracked in the `guest_mem_region.pages[]` array. This per-page tracking is required for several reasons:

- Host physical pages are not guaranteed to be contiguous even when guest physical addresses are. `alloc_page()` returns physically discontiguous pages in the general case.
- `kmap_local_page()` (used by `relm_vm_copy_to_guest`) operates on individual `struct page *` references.
- EPT mappings are per-page 4 KB leaf entries.

The `__GFP_ZERO` flag zeros each page before it is handed to the guest, preventing the guest from reading stale host kernel data.

### `guest_mem_region` Structure

```
struct guest_mem_region
├── gpa_start       uint64_t   Base GPA of this region (e.g. 0x0)
├── size            uint64_t   Total size in bytes (page-aligned)
├── pages           struct page **   Array of struct page*, one per 4KB page
├── num_pages       uint64_t   Length of pages[] array
├── flags           uint64_t   EPT permission flags (EPT_RWX)
└── next            *          Next region in the VM's linked list
```

Multiple regions form a singly-linked list rooted at `vm->mem_regions`. Lookup functions (in `relm_vm_copy_to_guest`, `relm_vm_copy_from_guest`, `relm_vm_zero_guest_memory`) walk this list to find the region containing a given GPA.

### Default Guest Physical Layout

With `Relm_VM_GUEST_RAM_SIZE = 128 MB` starting at GPA `0x0`:

```
GPA 0x00000000  ┌──────────────────────────────────────┐
                │                                      │
                │  Guest RAM (128 MB)                  │
                │  alloc_page() x 32768 pages          │
                │  EPT mapped: EPT_RWX                 │
                │                                      │
                │  Guest code/data/stack lives here.   │
                │  Initial GUEST_RIP = 0x0             │
                │  Initial GUEST_RSP = top of RAM - 16 │
                │                                      │
GPA 0x07FFD000  ├──────────────────────────────────────┤  ← total_guest_ram - 3*PAGE_SIZE
                │  Guest PML4 page (4 KB)              │
                │  alloc_page() - separate allocation  │
                │  EPT mapped: EPT_RWX                 │
GPA 0x07FFE000  ├──────────────────────────────────────┤
                │  Guest PDPT page (4 KB)              │
GPA 0x07FFF000  ├──────────────────────────────────────┤
                │  Guest PD page (4 KB)                │
GPA 0x08000000  └──────────────────────────────────────┘  (128 MB boundary)
```

The guest page table pages are placed at the top of guest RAM (`total_guest_ram - 3 * PAGE_SIZE`) to avoid conflicting with guest code and data that load from GPA 0x0 upward.

---

## Guest Page Tables

### Construction

Three separate 4 KB pages are allocated for the guest page table hierarchy (PML4, PDPT, PD) via `alloc_page(GFP_KERNEL | __GFP_ZERO)`. They are mapped into the EPT so the CPU can walk them when translating guest virtual addresses. The guest CR3 (`VMCS GUEST_CR3`) is set to `pml4_gpa`.

### Identity Mapping with 2 MB Pages

The guest page tables establish a **physical identity map** of the first 1 GB of guest address space using 2 MB pages (PS=1 in PD entries):

```
PML4[0]  →  pdpt_gpa | 0x7    (Present, R/W, User)
PDPT[0]  →  pd_gpa   | 0x7    (Present, R/W, User)

PD[0]    →  0x000000 | 0x87   (Present, R/W, User, PS=2MB page)
PD[1]    →  0x200000 | 0x87
PD[2]    →  0x400000 | 0x87
...
PD[511]  →  0x3FE00000 | 0x87  (covers 0x3FE00000 – 0x3FFFFFFF)
```

Each PD entry covers 2 MB (`0x200000` bytes). 512 entries × 2 MB = 1 GB total.

The identity map means `GVA == GPA` for all addresses in the first 1 GB. The guest does not need to set up its own page tables to access its code or data — the hypervisor has already done it. This simplifies the guest boot process: the very first instruction at GPA/GVA 0x0 runs correctly without any page-fault handling.

### Two-Walk Translation Example

```
Guest accesses GVA 0x1000 (second page of guest RAM):

Walk 1 (Guest page tables, using GUEST_CR3 = pml4_gpa):
  PML4[0]  → pdpt_gpa   (entry present)
  PDPT[0]  → pd_gpa     (entry present)
  PD[0]    → 0x000000 (2MB page, PS=1)
  GVA 0x1000 → GPA 0x1000

Walk 2 (EPT, using EPTP):
  EPT PML4[0]  → EPT PDPT page
  EPT PDPT[0]  → EPT PD page
  EPT PD[0]    → EPT PT page  (or 2MB leaf if used)
  EPT PT[1]    → HPA of the host page backing GPA 0x1000
  GPA 0x1000   → HPA (some physical page allocated by alloc_page)
```

The hardware performs both walks on the same TLB miss. The result (HPA) is cached in the TLB tagged with the VCPU's VPID so subsequent accesses to the same page skip both walks.

---

## Host-to-Guest Memory Access

When the hypervisor needs to read or write guest memory (e.g. to load a guest binary), it cannot dereference GPAs directly. GPAs are not host virtual addresses. Relm provides three functions that work through the `pages[]` array:

### `relm_vm_copy_to_guest`

For each 4 KB page in the destination GPA range:

```
1. Walk vm->mem_regions to find the region containing current_gpa
2. Compute page_index = (current_gpa - region->gpa_start) / PAGE_SIZE
3. Compute page_offset = (current_gpa - region->gpa_start) % PAGE_SIZE
4. page = region->pages[page_index]
5. page_va = kmap_local_page(page)     ← temporary kernel VA mapping
6. memcpy(page_va + page_offset, src, bytes_to_copy)
7. flush_dcache_page(page)             ← ensure DRAM visibility
8. kunmap_local(page_va)
```

`kmap_local_page()` creates a temporary kernel virtual address for the physical page. This is necessary because `alloc_page()` on a 64-bit kernel with sufficient RAM may return pages outside the direct-map region (above `PAGE_OFFSET`). `flush_dcache_page()` ensures the write is visible to hardware page table walkers and the guest CPU; `memcpy` writes go into the D-cache and are not guaranteed to reach DRAM until flushed on architectures with non-coherent caches (not strictly required on x86, but correct practice).

### `relm_vm_copy_from_guest`

Same page-walk mechanism in the reverse direction. `flush_dcache_page()` is omitted on reads (data flows from guest memory to host buffer, no cache coherency issue).

### `relm_vm_zero_guest_memory`

Uses `memset(page_va, 0, bytes)` + `set_page_dirty()` + `flush_dcache_page()`. `set_page_dirty()` marks the page as modified so the kernel's page reclaim path does not discard it silently.

---

## Extended Page Tables (EPT)

### EPTP Format

The EPTP written to `VMCS EPT_POINTER` encodes:

```
Bits [2:0]   Memory type for EPT paging structures (0=UC, 6=WB)
Bit  [3]     EPT page-walk length minus 1 (3 = 4-level walk)
Bit  [6]     Enable accessed/dirty flags in EPT entries
Bits [11:7]  Reserved (0)
Bits [N-1:12] Physical address of EPT PML4 (page-aligned, N = MAXPHYADDR)
```

Relm uses write-back memory type (6) and 4-level page walk (3), which is the standard configuration for 64-bit guests.

### EPT Entry Structure (Leaf, 4 KB page)

```
Bit  [0]   Read    (R): guest can read this page
Bit  [1]   Write   (W): guest can write this page
Bit  [2]   Execute (X): guest can execute from this page
Bits [5:3] Memory type (0=UC, 6=WB) for the mapped page
Bit  [7]   Ignore PAT
Bit  [8]   Accessed flag (set by hardware on read/write)
Bit  [9]   Dirty flag (set by hardware on write)
Bits [11:10] Reserved
Bits [N-1:12] Host physical address of the 4 KB page
```

All guest RAM regions are mapped with `EPT_RWX` (Read=1, Write=1, Execute=1). MMIO regions (not yet implemented) would use Read+Write with no Execute and a UC memory type.

### EPT Violation VM-Exits

When the guest accesses a GPA that is not in the EPT, or accesses a mapped GPA in a way that violates the permission bits, the CPU generates an EPT violation VM-exit. The exit qualification field in the VMCS encodes which access type caused the violation (read/write/fetch) and whether the GPA was mapped at all. The vmexit handler uses this to distinguish unmapped accesses (MMIO emulation) from permission violations (security policy enforcement).

---

## VMCS Region

### Allocation

```c
uint32_t vmcs_size = _get_vmcs_size();  // from MSR_IA32_VMX_BASIC[44:32]
size_t alloc_size = max(vmcs_size, PAGE_SIZE);
vcpu->vmcs = __get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(alloc_size));
*(uint32_t *)vcpu->vmcs = _vmcs_revision_id();  // MSR_IA32_VMX_BASIC[30:0]
vcpu->vmcs_pa = virt_to_phys(vcpu->vmcs);
```

The VMCS size is processor-model-specific, read from `MSR_IA32_VMX_BASIC` bits 44:32. It is always at least 4 KB and at most 4 KB on current hardware, but the code rounds up to the next power-of-two page count to be future-proof.

### VMCS Memory Layout

The VMCS format is entirely opaque to software. The Intel SDM states that software must treat the VMCS region as a black box, accessed only through `VMREAD` and `VMWRITE`. The only software-visible bytes are the first 4:

```
Offset 0   [31:0]  VMX revision identifier
                   Must match MSR_IA32_VMX_BASIC[30:0]
                   Set by software before VMCLEAR
                   Bit 31 is cleared by VMCLEAR and indicates shadow VMCS

Offset 4   onwards  Opaque to software
                    Contains all VMCS fields in a processor-defined encoding
                    Only accessible via VMREAD/VMWRITE with field encodings
                    from Intel SDM Vol 3C Appendix B
```

### VMCS Lifecycle

```
alloc_page()                      Memory allocated, revision ID written
      │
      ▼
VMCLEAR(vmcs_pa)                  Launch state set to "clear"
      │                           VMCS detached from all CPUs
      ▼
VMPTRLD(vmcs_pa)                  VMCS is now current on this CPU
      │
      ▼
VMWRITE × N                       All VMCS fields populated
      │
      ▼
VMLAUNCH                          Guest executes; launch state → "launched"
      │
      ▼  (VM-exits / VM-entries cycle)
      │
      ▼
VMCLEAR(vmcs_pa)                  Cleanup: flush to memory, detach from CPU
      │
      ▼
free_pages()                      Memory freed
```

---

## VCPU Host Stack

### Allocation and Layout

```c
vcpu->host_stack = __get_free_pages(GFP_KERNEL | __GFP_ZERO, HOST_STACK_ORDER);
// HOST_STACK_ORDER = 2  →  4 pages  →  16 KB

vcpu->host_rsp = ((uint64_t)vcpu->host_stack + HOST_STACK_SIZE - 0x100) & ~0xFULL;
```

```
host_stack base (low address)
      │
      │  ▲  stack grows downward
      │  │
      │  │  usable stack space (~15.75 KB)
      │  │  used by: relm_vmexit_handler, C vmexit dispatch, nested calls
      │  │
host_rsp ──────────────────────────────────────────  HOST_STACK_SIZE - 0x100, 16-byte aligned
      │
      │  0x100 bytes (256 bytes) guard/red-zone gap
      │  protects against: async NMI delivery on entry,
      │                    compiler red zone (128 bytes, System V ABI)
      │
top of allocation (high address, host_stack + HOST_STACK_SIZE)
```

`HOST_RSP` is written to the VMCS. On every VM-exit the CPU atomically restores RSP to this value before jumping to `HOST_RIP` (`relm_vmexit_handler`). This means the vmexit handler always starts with a valid, correctly aligned stack, even before any C prologue runs.

### Why 16 KB

Linux kernel threads default to 16 KB stacks (or 8 KB on older configs). The vmexit handler calls C functions that may call further functions. 16 KB matches the default and provides enough headroom for:
- The vmexit handler frame
- The exit reason dispatch function frame
- Any helper functions called from dispatch
- Guard space below `host_rsp`

`__GFP_ZERO` prevents stale host kernel data from being visible via stack reads if the guest manages to observe the host stack (not directly possible with EPT, but defensive).

---

## IO Bitmap

### Allocation

```c
size_t total = 2 * VMCS_IO_BITMAP_SIZE;   // 2 × 4 KB = 8 KB
vcpu->io_bitmap = __get_free_pages(GFP_KERNEL, get_order(total));
memset(vcpu->io_bitmap, 0, total);
vcpu->io_bitmap_pa = virt_to_phys(vcpu->io_bitmap);
```

The two 4 KB pages are allocated contiguously. Physical contiguity is required because the CPU addresses Bitmap B as `VMCS_IO_BITMAP_A_PA + 4096` — there is no separate `VMCS_IO_BITMAP_B` PA field that could point to a discontiguous page.

### Structure

```
io_bitmap_pa  →  [Bitmap A: 4 KB = 32768 bits]
                  Bit N = IO port N, for N = 0x0000 to 0x7FFF
                  Bit set   → VM-exit on IN/OUT for that port
                  Bit clear → access passes through silently

io_bitmap_pa + 4096  →  [Bitmap B: 4 KB = 32768 bits]
                          Bit N = IO port (N + 0x8000), for N = 0 to 32767
                          Covers ports 0x8000 to 0xFFFF
```

Relm initialises both bitmaps to all zeros (no IO port causes a VM-exit). Individual bits can be set to intercept specific ports. For example, to intercept port 0x3F8 (COM1 serial):

```c
uint32_t port = 0x3F8;
uint32_t byte = port / 8;  // 0x7F
uint8_t  bit  = port % 8;  // 0
bitmap_a[byte] |= (1 << bit);
```

The bitmap mechanism requires `VMCS_PROC_USE_IO_BITMAPS` to be set in primary processor-based execution controls. When this bit is clear, IO exits are controlled by `VMCS_PROC_UNCOND_IO_EXITING` (all IO exits or no IO exits). Relm sets both `VMCS_PROC_UNCOND_IO_EXITING` and `VMCS_PROC_USE_IO_BITMAPS` — when both are set, the bitmap takes precedence.

---

## MSR Bitmap

### Allocation

```c
vcpu->msr_bitmap = __get_free_page(GFP_KERNEL | __GFP_ZERO);  // 4 KB
vcpu->msr_bitmap_pa = virt_to_phys(vcpu->msr_bitmap);
```

### Structure

The MSR bitmap is a single 4 KB page divided into four 1 KB sections:

```
Offset 0x000 – 0x3FF  (1 KB):  Read bitmap for MSRs 0x00000000 – 0x00001FFF
                                Bit N → intercept RDMSR for MSR index N
Offset 0x400 – 0x7FF  (1 KB):  Read bitmap for MSRs 0xC0000000 – 0xC0001FFF
                                Bit N → intercept RDMSR for MSR (0xC0000000 + N)
Offset 0x800 – 0xBFF  (1 KB):  Write bitmap for MSRs 0x00000000 – 0x00001FFF
                                Bit N → intercept WRMSR for MSR index N
Offset 0xC00 – 0xFFF  (1 KB):  Write bitmap for MSRs 0xC0000000 – 0xC0001FFF
                                Bit N → intercept WRMSR for MSR (0xC0000000 + N)
```

MSRs outside these two ranges (any MSR with index 0x00002000–0xBFFFFFFF or 0xC0002000–0xFFFFFFFF) **always** cause a VM-exit, regardless of the bitmap.

Relm intercepts `IA32_SYSENTER_CS` (index 0x174) by setting its bit in the low read-bitmap (offset `0x174 / 8 = 0x2E`, bit `0x174 % 8 = 4`). All other MSRs are handled by the MSR load/store lists (EFER, STAR, LSTAR, etc.) and do not require bitmap interception.

Requires `VMCS_PROC_USE_MSR_BITMAPS` set in primary execution controls.

---

## MSR Load/Store Areas

### The Problem They Solve

The host kernel and the guest use the same MSR space but need different values. For example:
- `MSR_LSTAR` (syscall entry point): host has the kernel's `system_call_entry`; guest has its own syscall handler.
- `MSR_IA32_EFER`: both need `LME | LMA | SCE`, but the values may differ if the guest modifies EFER.
- `MSR_FS_BASE`: host uses FS_BASE for the `current` pointer (`per_cpu(current_task)`); guest uses it for its own per-thread data.

Without the MSR lists, the vmexit handler would call `RDMSR`/`WRMSR` for every managed MSR on every VM-exit — a serialising instruction pair with latency ~20–100 ns each. For 7 MSRs × 2 operations × thousands of exits per second, this is measurable overhead.

The hardware MSR lists eliminate all of this. The CPU performs the swaps as part of the VM-exit/entry microcode, with no software involvement.

### Three Lists

```
vmexit_store_area    [guest MSR values → memory on VM-exit]
                     CPU reads guest's current MSR values and writes them here
                     so the vmexit handler can inspect them if needed

vmexit_load_area     [memory → host MSR values on VM-exit]
                     CPU writes these values into the host's MSRs
                     restores the host environment before any C code runs

vmentry_load_area    [memory → guest MSR values on VM-entry]
                     CPU writes these values into the guest's MSRs
                     gives the guest its own EFER/LSTAR/etc. before first instruction
```

### Entry Format

Each list is an array of `struct msr_entry`:

```c
struct msr_entry {
    uint32_t index;     // MSR index (e.g. MSR_IA32_EFER = 0xC0000080)
    uint32_t reserved;  // must be zero
    uint64_t value;     // value to load (load areas) or destination (store areas)
};
```

### Relm's Managed MSR Set

| Index | Name | Why Managed |
|---|---|---|
| `0xC0000080` | `MSR_IA32_EFER` | LME/LMA/SCE bits; guest may differ from host |
| `0xC0000081` | `MSR_IA32_STAR` | Syscall CS/SS selectors |
| `0xC0000082` | `MSR_IA32_LSTAR` | 64-bit syscall entry RIP |
| `0xC0000083` | `MSR_IA32_CSTAR` | Compat-mode syscall entry RIP |
| `0xC0000084` | `MSR_IA32_FMASK` | RFLAGS mask on syscall |
| `0xC0000100` | `MSR_IA32_FS_BASE` | FS segment base; host uses for `current` pointer |
| `0xC0000101` | `MSR_IA32_GS_BASE` | GS segment base; host uses for per-CPU data |

### Allocation

Each list is allocated with `alloc_pages(GFP_KERNEL | __GFP_ZERO, order)` where order is computed to cover `n_entries × sizeof(struct msr_entry)` rounded up to whole pages. Physical addresses are stored in `vcpu->vmexit_store_pa`, `vcpu->vmexit_load_pa`, `vcpu->vmentry_load_pa`.

### Runtime Flow

```
VM-exit occurs:
  CPU reads MSRs listed in vmexit_store_area  →  writes values to vmexit_store_area[i].value
  CPU reads values from vmexit_load_area[i].value  →  writes to host MSRs
  [now host EFER/LSTAR/FS_BASE/GS_BASE etc. are restored]
  [host C code runs correctly]

VM-entry occurs:
  CPU reads values from vmentry_load_area[i].value  →  writes to guest MSRs
  [now guest EFER/LSTAR/FS_BASE etc. are set]
  [guest first instruction runs with correct MSR state]
```

---

## Per-CPU VMXON Region

### Allocation

One VMXON region per online CPU, allocated during `relm_vmx_enable_on_all_cpus()`:

```c
hcpu->vmxon = (struct vmxon_region *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
*(uint32_t *)hcpu->vmxon = _vmcs_revision_id();
hcpu->vmxon_pa = virt_to_phys(hcpu->vmxon);
```

### Format

Like the VMCS, the VMXON region is opaque to software. The only software-visible field is the first 4 bytes, which must contain the VMX revision identifier (same value as for the VMCS region). After `VMXON`, the CPU may use the region for its own internal bookkeeping; software must not read or write it while VMX operation is active.

### Lifecycle

```
kzalloc(host_cpu struct)          Allocated in sleepable context before IPI
setup_vmxon_region()              One page allocated, revision ID written
per_cpu(relm_per_cpu_hcpu) = hcpu Stored for IPI handler to find
    │
    ▼ IPI
VMXON(vmxon_pa)                   CPU enters VMX root operation
    │
    ▼ (VMX root operation active)
VMXOFF()                          module_exit: CPU exits VMX root operation
    │
free_page(vmxon)                  Memory freed
kfree(host_cpu)                   Struct freed
```

---

## Complete Memory Map per VCPU

The following shows all memory owned by a single VCPU after full initialisation, with approximate sizes and types:

```
Allocation                Size        Where           Notes
──────────────────────────────────────────────────────────────────────────
struct vcpu               ~600 B      kmalloc/SLAB    Central per-VCPU struct
host_stack                16 KB       buddy allocator order=2, contiguous
VMCS region               4 KB        buddy allocator order=0, 4KB aligned
IO bitmap A + B           8 KB        buddy allocator order=1, contiguous
MSR bitmap                4 KB        buddy allocator order=0
vmexit_store_area         ≤4 KB       buddy allocator holds 7 msr_entries
vmexit_load_area          ≤4 KB       buddy allocator holds 7 msr_entries
vmentry_load_area         ≤4 KB       buddy allocator holds 7 msr_entries
──────────────────────────────────────────────────────────────────────────
VCPU total (approx)       ~44 KB      (excluding guest RAM)
──────────────────────────────────────────────────────────────────────────
Guest RAM (128 MB)        128 MB      individual alloc_page() calls
Guest PML4/PDPT/PD pages  12 KB       3 × alloc_page(), separate from RAM
VMXON region (per CPU)    4 KB        buddy allocator, per physical CPU
──────────────────────────────────────────────────────────────────────────
Total system (1 VCPU)     ~128 MB + 60 KB
```

---

## Memory Ordering and Cache Coherence

### `flush_dcache_page` in Copy Functions

On x86 the D-cache is fully coherent with main memory for normal WB (write-back) cached pages. `flush_dcache_page()` is a no-op on x86. It is included because:

1. Relm targets x86 specifically but the pattern is correct for any architecture where `kmap_local_page` writes may not be immediately visible to hardware page table walkers.
2. Kernel coding convention requires it after `kmap_local_page` + `memcpy` writes.

### VMCS Write-Back Requirement

Intel SDM requires that VMCS regions be allocated with write-back memory type (the default for kernel allocations on x86). Allocating VMCS memory as write-combining or uncacheable would cause undefined behaviour. `__get_free_pages(GFP_KERNEL)` uses the direct mapping, which is WB by default.

### Physical Contiguity Requirements

| Structure | Contiguity Required | Reason |
|---|---|---|
| VMCS region | Yes (within allocation) | `vmcs_pa` must be a single physical address |
| VMXON region | Yes (1 page) | `vmxon_pa` must be a single physical address |
| IO bitmap A+B | Yes (2 contiguous pages) | Bitmap B is addressed as `bitmap_a_pa + 4096` |
| Host stack | Yes (4 contiguous pages) | `host_rsp` arithmetic assumes flat buffer |
| MSR areas | Yes (within allocation) | VMCS field holds a single PA for the array base |
| Guest RAM pages | No | Each page tracked individually in `pages[]`; EPT handles discontiguous mapping |

---

## Interaction With Other Documents

| Document | Relationship |
|---|---|
| `architecture.md` | Describes the components that own or use these memory structures |
| `vcpu_execution_model.md` | Describes when each structure is allocated (Phase 1) and when its PA is registered with the VMCS (Phase 2) |
