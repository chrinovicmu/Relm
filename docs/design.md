
# KVX hypervisor 

## Structure and Design 



### CPU Virtulization 

Based on Intel VT-x virtulization technology, KVX emulates a virtual vCPU with the following features. 

- One vCPU is dedicated and pinned to one physical CPU. 
- Each vCPU is identified as a Linux kernel thread for scheduling purposes. 


## vCPU states

A vCPU contains the following states: 
- **VPCU_STATE_UINITIALIZED** : Initial state of the vCPU on creation. The vCPU has not been configured yet. 
- **VPCU_STATE_INITIALIZED** : Ready to run (in the runqueue) 
- **VCPU_STATE_RUNNING** : Currently executing on a physical CPU/ 
- **VCPU_STATE_HALTED** : Executeds and HLT instruction, waiting for an interrupt. 
- **VCPU_STATE_BLOCKED** : Waiting for I/O or other host events. 
- **VCPU_STATE_SHUTDOWN** : Guest has signaled power off/triple fault. 
- **VCPU_STATE_ERROR** : Unrecoverable hypervisor/VMCS error. 

