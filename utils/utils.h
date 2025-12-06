#ifndef UTILS 
#define UTILS 

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/errno.h> 

#define CACHE_LINE_SIZE     64 

void* kzalloc_aligned(size_t size, size_t align, gfp_f flags) 
{
    void *ptr; 
    ptr = kzalloc(size + align -1, flags); 
    if(!ptr)
        return NULL; 

    return PTR_ALIGN(ptr, align); 
}


#endif // !UTILS 

