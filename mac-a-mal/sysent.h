/*
 * Copyright (c) fG!, 2011, 2012, 2013, 2014 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 * sysent.c
 *
 */

#ifndef onyx_sysent_h
#define onyx_sysent_h

//#include "sysproto.h"
#include "syscall.h"
#include <mach/kern_return.h>
#include <sys/types.h>
#include <mach/mach_vm.h>
#include <string.h>
#include <mach-o/loader.h>
#include <libkern/libkern.h>

void* find_sysent(mach_vm_address_t *out_kernel_base);
kern_return_t cleanup_sysent(void);
mach_vm_address_t calculate_int80address(const mach_vm_address_t idt_address);
mach_vm_address_t find_kernel_base(const mach_vm_address_t int80_address);

#endif

