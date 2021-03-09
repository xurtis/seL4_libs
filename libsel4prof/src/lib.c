/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <utils/base64.h>
#include <utils/cbor64.h>
#include <utils/arith.h>

#include <sel4runtime.h>
#include <sel4prof.h>
#include <sel4bench/sel4bench.h>

#define PROFILE_MAGIC 0x970F17E3
#define ENTRY_STACK_SIZE 128

/* Structure for counting function entries and exits */
typedef struct prof_node {
    struct prof_node *next;
    size_t magic;
    ccnt_t cycle_count;
    void *fn;
} prof_node_t;

/* The linked list of profile nodes */
static prof_node_t *prof_list;
static prof_node_t * volatile *prof_list_tail = &prof_list;

/* Most recent entry time */
static _Thread_local ccnt_t previous_cycles;

/* Mirror the call stack */
static _Thread_local size_t call_stack_depth = 0;
static _Thread_local prof_node_t *call_stack[ENTRY_STACK_SIZE];

SEL4PROF_NO_INSTRUMENT
static inline prof_node_t *node_from_fn(void *fn)
{
    uintptr_t node_addr = (uintptr_t)fn - sizeof(prof_node_t);
    node_addr -= node_addr % sizeof(prof_node_t);
    return (void *)node_addr;
}

SEL4PROF_NO_INSTRUMENT
static inline ccnt_t clamped_add(ccnt_t a, ccnt_t b)
{
    if (UINT64_MAX - a >= b) {
        return a + b;
    } else {
        return UINT64_MAX;
    }
}

/*
 * GCC generates calls to this function on instrumented function entry.
 *
 * @param this_fn    A pointer to the start of the function NOP area,
 *                   before the entry address.
 * @param call_site  A pointer the the call address.
 */
SEL4PROF_NO_INSTRUMENT
void __cyg_profile_func_enter (void *this_fn, void *call_site)
{
    if (sel4runtime_get_tls_base() == 0) return;

    /* Use the generated space at the start of the instrumented function
     * for profiling */
    prof_node_t *node = node_from_fn(this_fn);

    /* Read the cycle counter */
    ccnt_t counter = sel4bench_get_cycle_count();

    /* Initialise node */
    if (node->magic != PROFILE_MAGIC) {
        *node = (prof_node_t) {
            .next = NULL,
            .magic = PROFILE_MAGIC,
            .cycle_count = 0,
            .fn = this_fn,
        };
        prof_node_t *insert = node;
        while (insert != NULL) {
            prof_node_t *tail = __atomic_exchange_n(prof_list_tail, insert, __ATOMIC_SEQ_CST);
            prof_list_tail = &node->next;
            insert = tail;
        }
    }

    if (call_stack_depth > 0) {
        prof_node_t *caller;
        if (call_stack_depth <= ENTRY_STACK_SIZE) {
            caller = call_stack[call_stack_depth - 1];
        } else {
            caller = call_stack[ENTRY_STACK_SIZE - 1];
        }
        ccnt_t cycles = counter - previous_cycles;
        caller->cycle_count = clamped_add(caller->cycle_count, cycles);
    }

    /* Update the counter base for the next time window */
    previous_cycles = counter;

    /* Add the function to the call stack if there is space */
    if (call_stack_depth < ENTRY_STACK_SIZE) {
        call_stack[call_stack_depth] = node;
    }
    call_stack_depth += 1;
}

/*
 * GCC generates calls to this function on instrumented function exit.
 *
 * @param this_fn    A pointer to the start of the function NOP area,
 *                   before the entry address.
 * @param call_site  A pointer the the call address.
 */
SEL4PROF_NO_INSTRUMENT
void __cyg_profile_func_exit (void *this_fn, void *call_site)
{
    if (sel4runtime_get_tls_base() == 0 || call_stack_depth == 0) return;

    /* Read the cycle counter */
    ccnt_t counter = sel4bench_get_cycle_count();

    /* Get the cycles since the last counter read */
    ccnt_t cycles = counter - previous_cycles;

    /* Attribute the cycles to some call at the top of the stack*/
    prof_node_t *current;
    if (call_stack_depth <= ENTRY_STACK_SIZE) {
        current = call_stack[call_stack_depth - 1];
    } else {
        current = call_stack[ENTRY_STACK_SIZE - 1];
    }
    current->cycle_count = clamped_add(current->cycle_count, cycles);

    /* Update the counter base for the next time window */
    previous_cycles = counter;
    call_stack_depth -= 1;
}

/*
 * Dump the trace to stderr as cbor64 and reset
 */
SEL4PROF_NO_INSTRUMENT
int prof_dump(void)
{
    /* Start a new string domain */
    base64_t streamer = base64_new(stderr);

    fputs("PROFILE DUMP:\n", stderr);

    int err = cbor64_array_start(&streamer);
    if (err != 0) {
        return err;
    }

    prof_node_t *function = prof_list;
    while (function != NULL) {
        err = cbor64_array_length(&streamer, 2);
        if (err != 0) {
            return err;
        }

        err = cbor64_uint(&streamer, (uintptr_t)function->fn);
        if (err != 0) {
            return err;
        }

        err = cbor64_uint(&streamer, function->cycle_count);
        if (err != 0) {
            return err;
        }

        function->cycle_count = 0;
        function = function->next;
    }

    err = cbor64_array_end(&streamer);
    if (err != 0) {
        return err;
    }

    err = base64_terminate(&streamer);
    if (err != 0) {
        return err;
    }

    if (fputc('\n', stderr) != '\n') {
        return -1;
    } else {
        return 0;
    }
}
