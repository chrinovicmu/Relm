#ifndef VMCS_H
#define VMCS_H


struct vmcs{
    u32 revision_id;
    u32 abort;
    char data[0]
}__aligned(CONFIG_X86_OAGE_SIZE); 


