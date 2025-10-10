#ifndef _WATCHPOINT_MODULE_H
#define _WATCHPOINT_MODULE_H

#include <linux/perf_event.h>

#define MAX_SYMBOL_LEN 128

struct watchpoint_data {
    bool enabled;
    unsigned long address;
    struct perf_event * __percpu *wp_read;
    struct perf_event * __percpu *wp_write;
};

#endif
