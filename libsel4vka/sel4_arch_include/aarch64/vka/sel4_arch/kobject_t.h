/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#pragma once

#include <sel4/types.h>
#include <assert.h>
#include <autoconf.h>
#include <sel4vka/gen_config.h>
#include <utils/util.h>

enum _arm_mode_kobject_type {
    KOBJECT_FRAME = 0,
    KOBJECT_PAGE_GLOBAL_DIRECTORY,
    KOBJECT_PAGE_UPPER_DIRECTORY,
    KOBJECT_MODE_NUM_TYPES,
};

typedef int kobject_t;

/*
 * Get the size (in bits) of the untyped memory required to
 * create an object of the given size
 */
static inline seL4_Word arm_mode_kobject_get_size(kobject_t type, seL4_Word objectSize)
{
    switch (type) {
    /* ARM-specific frames. */
    case KOBJECT_FRAME:
        switch (objectSize) {
        case seL4_HugePageBits:
            return objectSize;
        default:
            return 0;
        }
    case KOBJECT_PAGE_UPPER_DIRECTORY:
        return seL4_PUDBits;
    default:
        /* Unknown object type. */
        ZF_LOGE("Unknown object type");
        return 0;
    }
}

static inline seL4_Word arm_mode_kobject_get_type(kobject_t type, seL4_Word objectSize)
{
    switch (type) {
    case KOBJECT_FRAME:
        switch (objectSize) {
        case seL4_HugePageBits:
            return seL4_ARM_HugePageObject;
        default:
            return -1;
        }
    case KOBJECT_PAGE_GLOBAL_DIRECTORY:
        return seL4_ARM_PageGlobalDirectoryObject;
    case KOBJECT_PAGE_UPPER_DIRECTORY:
        return seL4_ARM_PageUpperDirectoryObject;
    default:
        /* Unknown object type. */
        ZF_LOGE("Unknown object type %d", type);
        return -1;
    }
}

