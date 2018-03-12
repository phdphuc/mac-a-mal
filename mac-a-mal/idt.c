/*
 * Copyright (c) fG!, 2011, 2012, 2013, 2014 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 * sysent.c
 *
 */

#include "idt.h"

/* retrieve the address of the IDT
 * should never be a bogus value?
 */
void get_addr_idt(mach_vm_address_t *idt) {
	uint8_t idtr[10];
	__asm__ volatile ("sidt %0": "=m" (idtr));
	*idt = *(mach_vm_address_t *)(idtr+2);
}

// retrieve the size of the IDT
uint16_t  get_size_idt(void) {
	uint8_t idtr[10];
    uint16_t size = 0;
	__asm__ volatile ("sidt %0": "=m" (idtr));
	size = *((uint16_t *) &idtr[0]);
	return(size);
}
