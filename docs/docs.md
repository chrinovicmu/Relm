# Relm Hypervisor Technical Documentation

## Structure and Design

Relm is a Type-1 hypervisor integrated directly into the Linux kernel. It utilizes a VCPU-per-Kthread model, where each virtual processor is managed as a standard Linux task, allowing the host scheduler to manage CPU affinity while the hypervisor maintains hardware control.

## CPU Virtualization

Based on Intel VT-x hardware acceleration, Relm emulates virtual CPUs (vCPUs) with the following architectural features:

* **Processor Affinity**: Each vCPU is dedicated and pinned to a specific physical core to minimize cache thrashing and VM-exit overhead.
* **Execution Loop**: Every vCPU runs a high-priority kernel thread that manages the transition between Host and Guest modes via a custom assembly "trampoline."
* **Context Isolation**: Guest GPRs (General Purpose Registers) are captured and restored on the Host stack during every VM-Exit, ensuring the host kernel state remains untainted by guest execution.
* **Extensible Emulation**: A modular dispatch table (Ops table) allows for the seamless handling of intercepted instructions such as `CPUID`, `HLT`, and Port I/O.

## vCPU Lifecycle and States

The vCPU lifecycle is managed through a state machine that tracks the transition from allocation to execution and eventual termination.

| State | Description |
|-------|-------------|
| VCPU_STATE_UNINITIALIZED | The default state upon memory allocation. VMCS and register structures are allocated but not yet configured. |
| VCPU_STATE_INITIALIZED | Registers (RIP, RSP) are set, and the VMCS has been loaded via `VMPTRLD`. The vCPU is ready for the first `VMLAUNCH`. |
| VCPU_STATE_RUNNING | The vCPU has entered non-root operation. The physical CPU is currently executing guest instructions. |
| VCPU_STATE_HALTED | The guest executed a `HLT` instruction. The vCPU thread is unscheduled until a virtual interrupt is pending. |
| VCPU_STATE_BLOCKED | The vCPU is waiting for the host to complete a task, such as an I/O emulation or memory page allocation. |
| VCPU_STATE_SHUTDOWN | Final state. Triggered by a guest power-off request or an unhandled triple fault. Resources are ready for cleanup. |
| VCPU_STATE_ERROR | Hardware failure state. Triggered if `VM_INSTRUCTION_ERROR` is non-zero during a launch or resume attempt. |

## Memory Architecture

Relm implements a simplified memory model to ensure guest isolation:

* **Guest RAM**: Allocated as a contiguous block in the Host Virtual Address space using `vmalloc`.
* **Stack Initialization**: The Guest `RSP` is automatically mapped to the top of the allocated RAM block, growing downwards toward the Guest `RIP` at address `0x0`.
* **Instruction Interception**: Utilizing the Exception Bitmap, Relm traps specific events (like Page Faults or Invalid Opcodes) to maintain control over the execution environment.


##VM Memory layout:

The hypervisor organizes guest memory as a linked list of regions:

```

```struct Relm_vm 
    mem_regions

mem_regions: #1 
    gpa_start: 0x0 
    size: 2GB
    pages(0) -> page
    pages(1) ->  page 
    pages(...) - > page 
    next = mem_regions #2 

mem_regions # 2 
    gpa_start: 0xC00000000
    size: 512MB
    pages(0) -> page
    pages(1) -> page 
    pages(...) -> page 
    next NULL

` 
```
```
```
