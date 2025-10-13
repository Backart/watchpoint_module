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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Artem Maksymenko");
MODULE_DESCRIPTION("Kernel module for setting hardware watchpoints (read/write)");
MODULE_VERSION("0.2");

unsigned long wp_address = 0;
module_param(wp_address, ulong, 0644);
MODULE_PARM_DESC(wp_address, "Memory address to monitor (kernel virtual address)");

struct watchpoint_data wp_data;
static struct kobject *watchpoint_kobj;


static void wp_read_handler(struct perf_event *bp,
                            struct perf_sample_data *data,
                            struct pt_regs *regs)
{
    pr_emerg("[WATCHPOINT READ] Address: 0x%lx | Process: %s (PID %d) | CPU %d\n",
             wp_data.address, current->comm, current->pid, smp_processor_id());
    dump_stack();
}

static void wp_write_handler(struct perf_event *bp,
                             struct perf_sample_data *data,
                             struct pt_regs *regs)
{
    pr_emerg("[WATCHPOINT WRITE] Address: 0x%lx | Process: %s (PID %d) | CPU %d\n",
             wp_data.address, current->comm, current->pid, smp_processor_id());
    dump_stack();
}


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

static int set_watchpoint(unsigned long address)
{
    struct perf_event_attr attr;
    int cpu;
    int ret = 0;

    if (!address) {
        pr_err("Invalid address: 0x%lx\n", address);
        return -EINVAL;
    }

    /* address must be kernel virtual, not user-space */
    if (!virt_addr_valid((void *)address)) {
        pr_err("Address 0x%lx is not a valid kernel virtual address\n", address);
        return -EINVAL;
    }

    /* enforce 4-byte alignment */
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
    attr.bp_type = HW_BREAKPOINT_RW;  /* RW = both read and write */
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


static ssize_t address_show(struct kobject *kobj,
                            struct kobj_attribute *attr, char *buf)
{
    return scnprintf(buf, PAGE_SIZE, "0x%lx\n", wp_data.address);
}

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
