#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct relm_vm_exit_args {
    unsigned long long pad;
    unsigned int vcpu_id;
    unsigned long exit_reason;
    unsigned long guest_rip;
    unsigned long exit_qualification;
    unsigned long long exit_duration_ns;
    unsigned long long timestamp_ns;
};

struct exit_duration_ns
{
    unsigned long long count; 
    unsigned long long total_duration; 
    unsigned long long min_duration; 
    unsigned long long max_duration; 
}; 

struct{
    __uint(type, BPF_MAP_TYPE_HASH); 
    __uint(max_entries, 256); /*supports up to 256 exit reasons */ 
    __type(key, unsigned long); /*exit reason */ 
    __type(value, struct exit_stats); 
}exit_stats_map SEC(".maps");

SEC("tracepoint/relm/relm_vm_exit") 
int trace_relm_vm_exit(struct relm_vm_exit_args *ctx)
{
    unsigned long exit_reason = ctx->exit_reason; 
    struct exit_stats *stats; 
    struct exit_stats new_stats = {}; 

    stats = bpf_map_lookup_elem(&exit_stats_map, &exit_reason);

}
