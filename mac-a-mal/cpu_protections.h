/*
 * Copyright (c) fG!, 2011, 2012, 2013, 2014 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 * sysent.c
 *
 */

#ifndef onyx_cpu_protections_h
#define onyx_cpu_protections_h

#include <i386/proc_reg.h>
#include <mach/mach_types.h>

#define enable_interrupts() __asm__ volatile("sti");
#define disable_interrupts() __asm__ volatile("cli");

kern_return_t disable_wp(void);
kern_return_t enable_wp(void);
uint8_t verify_wp(void);
void enable_kernel_write(void);
void disable_kernel_write(void);

#endif