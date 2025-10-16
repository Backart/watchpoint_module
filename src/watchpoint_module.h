#ifndef _WATCHPOINT_MODULE_H
#define _WATCHPOINT_MODULE_H

#include <linux/perf_event.h>

/**
 * @file watchpoint_module.h
 * @brief Header file defining the data structure used by the Watchpoint kernel module.
 *
 * This module allows setting hardware watchpoints on a given kernel virtual address.
 * When the watched memory is accessed (read or write), registered callbacks are invoked.
 * The structure defined here stores the state and associated per-CPU perf_event handles
 * for monitoring read and write accesses.
 */

#define MAX_SYMBOL_LEN 128 /**< Maximum length for symbol names, if needed for future extensions */

/**
 * @struct watchpoint_data
 * @brief Represents the internal state of a hardware watchpoint.
 *
 * This structure maintains information about a single watchpoint, including whether
 * it is currently enabled, which memory address it monitors, and the per-CPU
 * perf_event handles used for read and write tracking.
 */
struct watchpoint_data {
    bool enabled; /**< Indicates if the watchpoint is currently active */
    unsigned long address; /**< Kernel virtual address being monitored */
    
    /**
     * @brief Per-CPU array of perf_event pointers for read monitoring.
     *
     * Each online CPU has its own perf_event instance to track read accesses to the
     * specified memory address. NULL if the read watchpoint is not set.
     */
    struct perf_event * __percpu *wp_read;

    /**
     * @brief Per-CPU array of perf_event pointers for write monitoring.
     *
     * Each online CPU has its own perf_event instance to track write accesses to the
     * specified memory address. NULL if the write watchpoint is not set.
     */
    struct perf_event * __percpu *wp_write;
};

#endif /* _WATCHPOINT_MODULE_H */
