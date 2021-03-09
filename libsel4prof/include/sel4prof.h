/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Attribute to indicate calls to a given function should not be
 * instrumented.
 */
#define SEL4PROF_NO_INSTRUMENT __attribute__((no_instrument_function))

/*
 * Dump the profile to stderr and reset counters.
 */
int prof_dump(void);

/*
 * Instrumentation functions for GCC.
 *
 * GCC inserts these autmoatically at function entries and exits, even
 * those that are inlined.
 */
void __cyg_profile_func_enter (void *this_fn, void *call_site);
void __cyg_profile_func_exit (void *this_fn, void *call_site);
