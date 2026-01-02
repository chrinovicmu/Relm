
#ifndef UTILS_H
#define UTILS_H

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <vmx_ops.h>

#define CACHE_LINE_SIZE 64

#define DEBOG_LOG 1

#if DEBOG_LOG
#define PDEBUG(fmt, ...) \
    printk(KERN_DEBUG "DEBUG : " fmt, ##__VA_ARGS__)
#else
#define PDEBUG(fmt, ...) \
    do {} while(0)
#endif

#define CHECK_VMWRITE(field_enc, value)                                 \
    do {                                                                 \
        if (_vmwrite((field_enc), (value))) {                             \
            printk(KERN_ERR "VMWrite failed: field_encoding: 0x%lx\n",   \
                   (unsigned long)(field_enc));                           \
            return -EIO;                                                  \
        }                                                                  \
    } while (0)

#define CHECK_VMREAD(field_enc, out_var)                                 \
    do {                                                                  \
        uint64_t __value;                                                 \
        if (_vmread_safe((field_enc), &__value)) {                         \
            printk(KERN_ERR "VMRead failed: field_encoding: 0x%lx\n",     \
                   (unsigned long)(field_enc));                            \
            return -EIO;                                                   \
        }                                                                  \
        (out_var) = __value;                                              \
    } while (0)

/* Functions */
static void* kzalloc_aligned(size_t size, size_t align, gfp_t flags)
{
    void *ptr;
    ptr = kzalloc(size + align - 1, flags);
    if (!ptr)
        return NULL;

    return PTR_ALIGN(ptr, align);
}

static bool check_cap(const char *name, unsigned long expected, unsigned long got)
{
    if (got != expected)
        pr_info("KVX %s: got %#lx expected %#lx\n", name, got, expected);

    return got != expected;
}

#endif /* UTILS_H */
