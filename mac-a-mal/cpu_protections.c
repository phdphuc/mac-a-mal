/*
 * Copyright (c) fG!, 2011, 2012, 2013, 2014 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 * sysent.c
 *
 */

#include "cpu_protections.h"

/*
 * disable the Write Protection bit in CR0 register
 * so we can modify kernel code
 */
kern_return_t disable_wp(void)
{
	uintptr_t cr0;
	// retrieve current value
	cr0 = get_cr0();
	// remove the WP bit
	cr0 = cr0 & ~CR0_WP;
	// and write it back
	set_cr0(cr0);
    // verify if we were successful
    if ((get_cr0() & CR0_WP) == 0) {
        return KERN_SUCCESS;
    } else {
        return KERN_FAILURE;
    }
}

/*
 * enable the Write Protection bit in CR0 register
 */
kern_return_t enable_wp(void)
{
	uintptr_t cr0;
	// retrieve current value
	cr0 = get_cr0();
	// add the WP bit
	cr0 = cr0 | CR0_WP;
	// and write it back
	set_cr0(cr0);
    // verify if we were successful
    if ((get_cr0() & CR0_WP) != 0) {
        return KERN_SUCCESS;
    } else {
        return KERN_FAILURE;
    }
}

/*
 * check if WP is set or not
 * 0 - it's set
 * 1 - not set
 */
uint8_t verify_wp(void) {
    uintptr_t cr0;
    cr0 = get_cr0();
    if (cr0 & CR0_WP) {
        return 0;
    } else {
        return 1;
    }
}

void enable_kernel_write(void) {
    disable_interrupts();
    disable_wp();
}

void disable_kernel_write(void) {
    enable_wp();
    enable_interrupts();
}
