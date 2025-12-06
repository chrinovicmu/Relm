
#ifndef MACRO_H 
#define MACRO_H

#include <linux/kernel.h> 

#define DEBOG_LOG  1 

#if DEBOG_LOG 
    #define PDEBUG(fmt, ...) \
        printk(KERN_DEBUG "DEBUG : " fmt, ##__VA_ARGS__)
#else
    #define PDEBUG(fmt, ...) \
        do {} while(0)
#endif

#define CHECK_VMWRITE(field_enc, value)                                 \
    do {                                                               \
        if (_vmwrite((field_enc), (value))) {                           \
            printk(KERN_ERR "VMWrite failed: field_encoding: 0x%lx\n", \
                   (unsigned long)(field_enc));                         \
            return -EIO;                                                \
        }                                                              \
    } while (0)


#define CHECK_VMREAD(field_enc, out_var)                                   \
    do {                                                                   \
        uint64_t __value;                                                  \
        if (_vmread((field_enc), &__value)) {                              \
            printk(KERN_ERR "VMRead failed: field_encoding: 0x%lx\n",     \
                   (unsigned long)(field_enc));                            \
            return -EIO;                                                   \
        }                                                                  \
        (out_var) = __value;                                               \
    } while (0)

#endif 
