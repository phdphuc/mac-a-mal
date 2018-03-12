/*
 * Copyright (c) fG!, 2011, 2012, 2013, 2014 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 * sysent.c
 *
 */

#ifndef onyx_idt_h
#define onyx_idt_h

#include <stdint.h>
#include <mach/vm_types.h>

uint16_t get_size_idt(void);
void get_addr_idt (mach_vm_address_t* idt);

#endif