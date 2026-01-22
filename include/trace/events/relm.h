#undef TRACE_SYSTEM
#define TRACE_SYSTEM relm 

#if !defined(_TRACE_RELM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RELM_H

#include <linux/tracepoint.h> 

TRACE_EVENT(relm_vm_exit, 

    TP_PROTO(unsigned int vpid, 
             unsigned long exit_reason, 
             unsigned long guest_rip, 
             unsigned long exit_qualification, 
             u64 exit_duration_ns),

    TP_ARGS(vpid, exit_reason, guest_rip, exit_qualification, exit_duration_ns), 

    TP_STRUCT__entry(
        __field(unsigned int, vpid)
        __field(unsigned long, exit_reason)
        __field(unsigned long, guest_rip)
        __field(unsigned long, exit_qualification)
        __field(u64, exit_duration_ns)
        __field(u64, timestamp_ns) /* Fixed: Added missing comma */
    ), 

    TP_fast_assign(
        __entry->vpid = vpid; 
        __entry->exit_reason = exit_reason; 
        __entry->guest_rip = guest_rip; 
        __entry->exit_qualification = exit_qualification; 
        __entry->exit_duration_ns = exit_duration_ns; 
        __entry->timestamp_ns = ktime_get_ns(); 
    ),

    TP_printk("vpid=%u reason=0x%lx rip=0x%lx qualification=0x%lx duration=%llu ns timestamp=%llu",
              __entry->vpid,
              __entry->exit_reason,
              __entry->guest_rip,
              __entry->exit_qualification,
              __entry->exit_duration_ns,
              __entry->timestamp_ns)
);

TRACE_EVENT(relm_vm_entry,

    TP_PROTO(unsigned int vpid,
             unsigned long guest_rip),

    TP_ARGS(vpid, guest_rip),

    TP_STRUCT__entry(
        __field(unsigned int, vpid)
        __field(unsigned long, guest_rip)
        __field(u64, timestamp_ns)
    ),

    TP_fast_assign(
        __entry->vpid = vpid;
        __entry->guest_rip = guest_rip;
        __entry->timestamp_ns = ktime_get_ns();
    ),

    TP_printk("vpid=%u rip=0x%lx timestamp=%llu",
              __entry->vpid,
              __entry->guest_rip,
              __entry->timestamp_ns)
);

#endif /* _TRACE_RELM_H */

/* This part must be outside the header guard */
#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE

#define TRACE_INCLUDE_PATH include/trace/events
#define TRACE_INCLUDE_FILE relm
#include <trace/define_trace.h>
