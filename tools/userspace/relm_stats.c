#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct exit_stats {
    unsigned long long count;
    unsigned long long total_duration;
    unsigned long long min_duration;
    unsigned long long max_duration;
};

const char* exit_reason_name(unsigned long reason) 
{
    switch(reason) 
    {
        case 0: return "EXCEPTION_NMI";
        case 1: return "EXTERNAL_INTERRUPT";
        case 10: return "CPUID";
        case 12: return "HLT";
        case 28: return "CR_ACCESS";
        case 30: return "IO_INSTRUCTION";
        case 48: return "EPT_VIOLATION";
        default: return "UNKNOWN";
    }
}

int main(int argc, char *argv[])
{
    struct bpf_object *obj; 
    struct bpf_prgram *prog; 
    int map_fd; 
    int prog_fd; 
    struct bpf_link *link;

    obj = bpf_object__open_file("relm_trace.o", NULL); 
    if(!obj){
        fprintf(stderr, "Failed to open BPF object\n"); 
        return 1; 
    }

    if(bpf_object__load(obj)){
        fprintf(stderr, "Failed tp load BPF object\n"); 
        return 1; 
    }

    prog = bpf_object__find_program_by_name(obj, "trace_relm_vm_exit"); 
    if(!prog){
        fprintf(stderr, "Failed to find BPF program\n");
        return 1; 
    }

    link = bpf_program__attach(prog); 
    if(!link){
        fprintf(stderr, "Failed to attach BPF program\n"); 
        return 1; 
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "exit_stats_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find BPF map\n");
        return 1;
    }

    printf("Tracing VM exits... Press Ctrl+C to stop\n\n");

    while (1) {
        sleep(2);
        
        printf("\033[2J\033[H");
        printf("VM Exit Statistics:\n");
        printf("%-20s %10s %15s %15s %15s %12s\n",
               "Exit Reason", "Count", "Total (ms)", "Avg (µs)", "Min (µs)", "Max (µs)");
        printf("─────────────────────────────────────────────────────────────────────────────────\n");

        unsigned long key = 0, next_key;
        struct exit_stats stats;
        
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) 
        {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) 
            {
                unsigned long long avg_ns = stats.count > 0 ? 
                    stats.total_duration / stats.count : 0;
                
                printf("%-20s %10llu %15.2f %15.2f %15.2f %12.2f\n",
                       exit_reason_name(next_key),
                       stats.count,
                       stats.total_duration / 1000000.0,  
                       avg_ns / 1000.0,                   
                       stats.min_duration / 1000.0,       
                       stats.max_duration / 1000.0);      
            }
            key = next_key;
        }
    }

    return 0;
}
