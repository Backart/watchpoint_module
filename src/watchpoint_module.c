/**
 * @file watchpoint_module.c
 * @brief Linux kernel module for setting hardware watchpoints on kernel memory.
 *
 * This module allows monitoring a specified kernel virtual address. When the address
 * is accessed (read or write), user-defined callbacks are invoked, and a backtrace
 * is printed. The module exposes sysfs entries to set the monitored address dynamically
 * and check whether the watchpoint is enabled.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/smp.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include "watchpoint_module.h"

/** 
 * @brief Module parameter for the memory address to monitor.
 * 
 * Can be set at module load time via insmod or dynamically via sysfs.
 */

unsigned long wp_address = 0;
module_param(wp_address, ulong, 0644);
MODULE_PARM_DESC(wp_address, "Memory address to monitor (kernel virtual address)");

/** Global data structure storing watchpoint state */
struct watchpoint_data wp_data;

/** Kobject for sysfs interface */
static struct kobject *watchpoint_kobj;

/* ===========================
 * Watchpoint callback handlers
 * =========================== */

/**
 * @brief Callback for read accesses to the watched address.
 *
 * This function is called by the perf_event infrastructure whenever
 * a read occurs on the monitored address. It logs information and
 * prints a stack trace.
 *
 * @param bp Pointer to the perf_event triggering the callback.
 * @param data Sample data (unused).
 * @param regs CPU registers at the time of the access.
 */
static void wp_read_handler(struct perf_event *bp,
                            struct perf_sample_data *data,
                            struct pt_regs *regs)
{
    pr_emerg("[WATCHPOINT READ] Address: 0x%lx | Process: %s (PID %d) | CPU %d\n",
             wp_data.address, current->comm, current->pid, smp_processor_id());
    dump_stack();
}

/**
 * @brief Callback for write accesses to the watched address.
 *
 * This function is called by the perf_event infrastructure whenever
 * a write occurs on the monitored address. It logs information and
 * prints a stack trace.
 *
 * @param bp Pointer to the perf_event triggering the callback.
 * @param data Sample data (unused).
 * @param regs CPU registers at the time of the access.
 */
static void wp_write_handler(struct perf_event *bp,
                             struct perf_sample_data *data,
                             struct pt_regs *regs)
{
    pr_emerg("[WATCHPOINT WRITE] Address: 0x%lx | Process: %s (PID %d) | CPU %d\n",
             wp_data.address, current->comm, current->pid, smp_processor_id());
    dump_stack();
}

/* ===========================
 * Watchpoint management
 * =========================== */

/**
 * @brief Remove the currently active watchpoint.
 *
 * Releases all per-CPU perf_event resources and marks the watchpoint
 * as disabled.
 */
static void remove_watchpoint(void)
{
    int cpu;

    if (!wp_data.enabled)
        return;

    pr_info("Removing watchpoint at 0x%lx\n", wp_data.address);

    if (wp_data.wp_read) {
        for_each_online_cpu(cpu) {
            struct perf_event **pe = per_cpu_ptr(wp_data.wp_read, cpu);
            if (*pe) {
                perf_event_release_kernel(*pe);
                *pe = NULL;
            }
        }
        free_percpu(wp_data.wp_read);
        wp_data.wp_read = NULL;
    }

    if (wp_data.wp_write) {
        for_each_online_cpu(cpu) {
            struct perf_event **pe = per_cpu_ptr(wp_data.wp_write, cpu);
            if (*pe) {
                perf_event_release_kernel(*pe);
                *pe = NULL;
            }
        }
        free_percpu(wp_data.wp_write);
        wp_data.wp_write = NULL;
    }

    wp_data.enabled = false;
    wp_data.address = 0;
}

/**
 * @brief Set a hardware watchpoint on the specified address.
 *
 * Allocates per-CPU perf_event resources and registers read/write callbacks.
 * Performs validation on the address and enforces 4-byte alignment.
 *
 * @param address Kernel virtual address to monitor.
 * @return 0 on success, negative error code on failure.
 */
static int set_watchpoint(unsigned long address)
{
    struct perf_event_attr attr;
    int cpu;
    int ret = 0;

    if (!address) {
        pr_err("Invalid address: 0x%lx\n", address);
        return -EINVAL;
    }

    if (!virt_addr_valid((void *)address)) {
        pr_err("Address 0x%lx is not a valid kernel virtual address\n", address);
        return -EINVAL;
    }

    if (address & 0x3) {
        pr_warn("Address 0x%lx not aligned, aligning down to 0x%lx\n",
                address, address & ~0x3UL);
        address &= ~0x3UL;
    }

    remove_watchpoint();

    memset(&attr, 0, sizeof(attr));
    hw_breakpoint_init(&attr);
    attr.bp_addr = address;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_RW;
    attr.disabled = false;

    wp_data.wp_read = alloc_percpu(struct perf_event *);
    if (!wp_data.wp_read)
        return -ENOMEM;

    for_each_online_cpu(cpu) {
        struct perf_event *pe = perf_event_create_kernel_counter(
            &attr, cpu, NULL, wp_write_handler, NULL);

        if (IS_ERR(pe)) {
            ret = PTR_ERR(pe);
            pr_err("Failed to create HW breakpoint on CPU %d: %d\n", cpu, ret);
            goto fail_cleanup;
        }
        *per_cpu_ptr(wp_data.wp_read, cpu) = pe;
    }

    wp_data.address = address;
    wp_data.enabled = true;

    pr_info("Watchpoint successfully set at 0x%lx\n", address);
    return 0;

fail_cleanup:
    for_each_online_cpu(cpu) {
        struct perf_event **pe = per_cpu_ptr(wp_data.wp_read, cpu);
        if (*pe) {
            perf_event_release_kernel(*pe);
            *pe = NULL;
        }
    }
    free_percpu(wp_data.wp_read);
    wp_data.wp_read = NULL;
    return ret;
}

/* ===========================
 * Sysfs interface
 * =========================== */

/**
 * @brief Show current watchpoint address via sysfs.
 */
static ssize_t address_show(struct kobject *kobj,
                            struct kobj_attribute *attr, char *buf)
{
    return scnprintf(buf, PAGE_SIZE, "0x%lx\n", wp_data.address);
}

/**
 * @brief Set a new watchpoint address via sysfs.
 */
static ssize_t address_store(struct kobject *kobj,
                             struct kobj_attribute *attr,
                             const char *buf, size_t count)
{
    unsigned long new_addr;
    int ret = kstrtoul(buf, 0, &new_addr);
    if (ret)
        return ret;

    ret = set_watchpoint(new_addr);
    if (ret)
        return ret;

    return count;
}

/**
 * @brief Show whether the watchpoint is enabled via sysfs.
 */
static ssize_t enabled_show(struct kobject *kobj,
                            struct kobj_attribute *attr, char *buf)
{
    return scnprintf(buf, PAGE_SIZE, "%d\n", wp_data.enabled);
}

static struct kobj_attribute address_attribute =
    __ATTR(address, 0644, address_show, address_store);
static struct kobj_attribute enabled_attribute =
    __ATTR(enabled, 0444, enabled_show, NULL);

static struct attribute *attrs[] = {
    &address_attribute.attr,
    &enabled_attribute.attr,
    NULL,
};

static struct attribute_group attr_group = {
    .attrs = attrs,
};

/* ===========================
 * Module init/exit
 * =========================== */

/**
 * @brief Initialize the watchpoint module.
 *
 * Creates the sysfs interface and optionally sets an initial watchpoint
 * if the module parameter wp_address is specified.
 *
 * @return 0 on success, negative error code on failure.
 */
static int __init watchpoint_init(void)
{
    int ret;

    pr_info("Watchpoint module loading\n");
    memset(&wp_data, 0, sizeof(wp_data));

    watchpoint_kobj = kobject_create_and_add("watchpoint", kernel_kobj);
    if (!watchpoint_kobj)
        return -ENOMEM;

    ret = sysfs_create_group(watchpoint_kobj, &attr_group);
    if (ret) {
        kobject_put(watchpoint_kobj);
        return ret;
    }

    if (wp_address) {
        ret = set_watchpoint(wp_address);
        if (ret)
            pr_warn("Failed to set initial watchpoint: %d\n", ret);
    }

    pr_info("Watchpoint module loaded successfully\n");
    return 0;
}

/**
 * @brief Cleanup the watchpoint module.
 *
 * Removes the active watchpoint and deletes the sysfs interface.
 */
static void __exit watchpoint_exit(void)
{
    pr_info("Unloading watchpoint module\n");
    remove_watchpoint();

    if (watchpoint_kobj) {
        sysfs_remove_group(watchpoint_kobj, &attr_group);
        kobject_put(watchpoint_kobj);
    }
}

module_init(watchpoint_init);
module_exit(watchpoint_exit);
