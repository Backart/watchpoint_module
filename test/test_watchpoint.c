/**
 * @file test_watchpoint.c
 * @brief Simple user-space program to test the Linux kernel watchpoint module.
 *
 * This program defines a variable in memory and performs read and write
 * accesses to it. If the kernel module has been loaded and a watchpoint
 * has been set on this address, callbacks in the kernel module should
 * be triggered, logging messages and backtraces to the kernel log (dmesg).
 *
 * @section usage Usage Instructions
 *
 * 1. **Build the kernel module and test program**:
 *    ```bash
 *    cd ~/../watchpoint_module
 *    make all
 *    ```
 *    This will compile:
 *      - `watchpoint_module.ko` (kernel module)
 *      - `test/test_watchpoint` (user-space test)
 *
 * 2. **Load the kernel module and set the watchpoint**:
 *    If you know the address of your test variable (printed by the program):
 *    ```bash
 *    sudo insmod src/watchpoint_module.ko wp_address=0x<addr_to_watch>
 *    ```
 *    Or dynamically via sysfs:
 *    ```bash
 *    sudo insmod src/watchpoint_module.ko
 *    echo 0x<addr_to_watch> | sudo tee /sys/kernel/watchpoint/address
 *    ```
 *
 * 3. **Run the user-space test**:
 *    ```bash
 *    ./test/test_watchpoint
 *    ```
 *
 * 4. **Check kernel log for watchpoint triggers**:
 *    ```bash
 *    dmesg | tail -n 20
 *    ```
 *    Expected lines:
 *    ```
 *    [WATCHPOINT WRITE] Address: 0xffffffff... | Process: test_watchpoint (PID ...) | CPU ...
 *    [WATCHPOINT READ] Address: 0xffffffff... | Process: test_watchpoint (PID ...) | CPU ...
 *    ```
 *
 * 5. **Unload the kernel module after testing**:
 *    ```bash
 *    sudo rmmod watchpoint_module
 *    ```
 *
 * @note Replace `0x<addr_to_watch>` with the memory address printed by the program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <string.h>

/** 
 * @brief External symbol from the kernel module, for reference.
 *
 * Not actually linked; demonstrates existence of module parameter.
 */
extern unsigned long wp_address; 

int main(void) {
    unsigned long addr_to_watch;
    volatile int test_var = 0;

    // Determine the memory address to monitor
    addr_to_watch = (unsigned long)&test_var;

    printf("Testing watchpoint on address: %p\n", (void*)addr_to_watch);

    // Write access to the watched variable
    printf("Writing 42 to watched variable...\n");
    test_var = 42;

    // Read access to the watched variable
    printf("Reading watched variable: %d\n", test_var);

    printf("Check 'dmesg' to see if module callbacks were called.\n");

    return 0;
}
