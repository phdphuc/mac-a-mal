/*
 * Copyright (c) fG!, 2011, 2012, 2013, 2014 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 * sysent.c
 *
 * Pham Duy Phuc - Update to work til MacOS SIERRA.
 */
#include "sysent.h"
#include "cpu_protections.h"
#include "my_data_definitions.h"
#include "idt.h"

// global vars
void *g_sysent_addr;
struct sysent *g_sysent;
struct sysent_mavericks *g_sysent_mav;
struct sysent_yosemite *g_sysent_yos;

/* to distinguish between Mavericks and others because of different sysent structure */
extern const int  version_major;

// 16 bytes IDT descriptor, used for 32 and 64 bits kernels (64 bit capable cpus!)
struct descriptor_idt
{
	uint16_t offset_low;
	uint16_t seg_selector;
	uint8_t reserved;
	uint8_t flag;
	uint16_t offset_middle;
	uint32_t offset_high;
	uint32_t reserved2;
};

// local functions
static uint8_t process_header(const mach_vm_address_t target_address, const char *segment_name, uint64_t *segment_address, uint64_t *seg_size);
static void* bruteforce_sysent(mach_vm_address_t *out_kernel_base);

#pragma mark Externally available functions

/*
 * external available function to find sysent table
 * if it fails then kext loading will have to fail
 */
void* find_sysent(mach_vm_address_t *out_kernel_base)
{
    LOG_DEBUG("Finding sysent table...");
    // retrieve sysent address
    g_sysent_addr = bruteforce_sysent(out_kernel_base);
    // if we can't find it return a kernel module failure
    if (g_sysent_addr == NULL)
    {
        LOG_ERROR("Cannot find sysent table");
        return NULL;
    }
    switch (version_major)
    {
        case SIERRA:
        case EL_CAPITAN:
        case YOSEMITE:
            g_sysent_yos = (struct sysent_yosemite*)g_sysent_addr;
            break;
        case MAVERICKS:
            g_sysent_mav = (struct sysent_mavericks*)g_sysent_addr;
            break;
        default:
            g_sysent = (struct sysent*)g_sysent_addr;
            break;
    }
    return g_sysent_addr;
}


/*
 * calculate the address of the kernel int80 handler
 * using the IDT array
 */
mach_vm_address_t
calculate_int80address(const mach_vm_address_t idt_address)
{
  	// find the address of interrupt 0x80 - EXCEP64_SPC_USR(0x80,hi64_unix_scall) @ osfmk/i386/idt64.s
	struct descriptor_idt *int80_descriptor = NULL;
	mach_vm_address_t int80_address = 0;
    // we need to compute the address, it's not direct
    // extract the stub address
#if __LP64__
    // retrieve the descriptor for interrupt 0x80
    // the IDT is an array of descriptors
    int80_descriptor = (struct descriptor_idt*)(idt_address+sizeof(struct descriptor_idt)*0x80);
    uint64_t high = (unsigned long)int80_descriptor->offset_high << 32;
    uint32_t middle = (unsigned int)int80_descriptor->offset_middle << 16;
    int80_address = (mach_vm_address_t)(high + middle + int80_descriptor->offset_low);
#else
    int80_descriptor = (struct descriptor_idt*)(idt_address+sizeof(struct descriptor_idt)*0x80);
    int80_address = (mach_vm_address_t)(int80_descriptor->offset_middle << 16) + int80_descriptor->offset_low;
#endif
	LOG_DEBUG("Address of interrupt 80 stub is 0x%llx", int80_address);
    return int80_address;
}

/*
 * find the kernel base address (mach-o header)
 * by searching backwards using the int80 handler as starting point
 */
mach_vm_address_t
find_kernel_base(const mach_vm_address_t int80_address)
{
    mach_vm_address_t temp_address = int80_address;
#if __LP64__
    struct segment_command_64 *segment_command = NULL;
    while (temp_address > 0)
    {
        if (*(uint32_t*)(temp_address) == MH_MAGIC_64)
        {
            // make sure it's the header and not some reference to the MAGIC number
            segment_command = (struct segment_command_64*)(temp_address + sizeof(struct mach_header_64));
            if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
            {
                LOG_DEBUG("Found kernel mach-o header address at %p", (void*)(temp_address));
                return temp_address;
            }
        }
        if (temp_address - 1 > temp_address) break;
        temp_address--;
    }
#else
    struct segment_command *segment_command = NULL;
    while (temp_address > 0)
    {
        if (*(uint32_t*)((uint32_t)temp_address) == MH_MAGIC)
        {
            // make sure it's the header and not some reference to the MAGIC number
            segment_command = (struct segment_command*)((uint32_t)temp_address + sizeof(struct mach_header));
            if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
            {
                LOG_DEBUG("Found kernel mach-o header address at %p", (void*)((uint32_t)temp_address));
                return (mach_vm_address_t)temp_address;
            }
        }
        if (temp_address - 1 > temp_address)
        {
            break;
        }
        temp_address--;
    }
#endif
    return 0;
}

#pragma mark Local functions

/*
 * brute force search sysent
 * this method works in all versions
 * returns a pointer to the sysent structure
 * Note: 32/64 bits compatible
 */
static void *
bruteforce_sysent(mach_vm_address_t *out_kernel_base)
{
    // retrieves the address of the IDT
    mach_vm_address_t idt_address = 0;
    get_addr_idt(&idt_address);
    LOG_DEBUG("IDT Address is 0x%llx", idt_address);
    // calculate the address of the int80 handler
    mach_vm_address_t int80_address = calculate_int80address(idt_address);
    // search backwards for the kernel base address (mach-o header)
    mach_vm_address_t kernel_base = find_kernel_base(int80_address);
    *out_kernel_base = kernel_base;
    uint64_t segment_address = 0;
    uint64_t segment_size = 0;
    if (version_major >= SIERRA) {
        // search for the __CONST segment
        process_header(kernel_base, "__CONST", &segment_address, &segment_size);
    } else {
        // search for the __DATA segment
        process_header(kernel_base, "__DATA", &segment_address, &segment_size);
    }
    uint64_t segment_limit = segment_address + segment_size;
    // bruteforce search for sysent in __DATA segment
    while (segment_address <= segment_limit)
    {
        if (version_major >= YOSEMITE)
        {
            struct sysent_yosemite *table = (struct sysent_yosemite*)segment_address;
            if((void*)table != NULL &&
               table[SYS_exit].sy_narg      == 1 &&
               table[SYS_fork].sy_narg      == 0 &&
               table[SYS_read].sy_narg      == 3 &&
               table[SYS_wait4].sy_narg     == 4 &&
               table[SYS_ptrace].sy_narg    == 4 &&
               table[SYS_getxattr].sy_narg  == 6 &&
               table[SYS_listxattr].sy_narg == 4 &&
               table[SYS_recvmsg].sy_narg   == 3 )
            {
                LOG_DEBUG("exit() address is %p", (void*)table[SYS_exit].sy_call);
                return (void*)segment_address;
            }
        }
        /* mavericks or higher */
        else if (version_major == MAVERICKS)
        {
            struct sysent_mavericks *table = (struct sysent_mavericks*)segment_address;
            if((void*)table != NULL &&
               table[SYS_exit].sy_narg      == 1 &&
               table[SYS_fork].sy_narg      == 0 &&
               table[SYS_read].sy_narg      == 3 &&
               table[SYS_wait4].sy_narg     == 4 &&
               table[SYS_ptrace].sy_narg    == 4 &&
               table[SYS_getxattr].sy_narg  == 6 &&
               table[SYS_listxattr].sy_narg == 4 &&
               table[SYS_recvmsg].sy_narg   == 3 )
            {
                LOG_DEBUG("exit() address is %p", (void*)table[SYS_exit].sy_call);
                return (void*)segment_address;
            }
        }
        /* all previous versions */
        else
        {
            struct sysent *table = (struct sysent*)segment_address;
            if((void*)table != NULL &&
               table[SYS_exit].sy_narg      == 1 &&
               table[SYS_fork].sy_narg      == 0 &&
               table[SYS_read].sy_narg      == 3 &&
               table[SYS_wait4].sy_narg     == 4 &&
               table[SYS_ptrace].sy_narg    == 4 &&
               table[SYS_getxattr].sy_narg  == 6 &&
               table[SYS_listxattr].sy_narg == 4 &&
               table[SYS_recvmsg].sy_narg   == 3 )
            {
                LOG_DEBUG("exit() address is %p", (void*)table[SYS_exit].sy_call);
                return (void*)segment_address;
            }
        }
        segment_address++;
    }
    return NULL;
}


/* 
 * process target kernel module header and retrieve some info we need
 * more specifically the __DATA segment
 */
static uint8_t
process_header(const mach_vm_address_t target_address, const char *segment_name, uint64_t *segment_address, uint64_t *seg_size)
{
    // verify if it's a valid mach-o binary
    struct mach_header *mh = (struct mach_header*)target_address;
    int header_size = sizeof(struct mach_header);
    switch (mh->magic) {
        case MH_MAGIC:
            break;
        case MH_MAGIC_64:
            header_size = sizeof(struct mach_header_64);
            break;
        default:
            LOG_ERROR("Not a valid mach-o binary address passed to %s", __FUNCTION__);
            return 1;
    }
    
    // find the last command offset
    struct load_command *load_cmd = NULL;
    char *load_cmd_addr = (char*)target_address + header_size;
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        switch (load_cmd->cmd)
        {
            case LC_SEGMENT:
            {
                struct segment_command *segmentCommand = (struct segment_command *)load_cmd;
                if (strncmp(segmentCommand->segname, segment_name, 16) == 0)
                {
                    *segment_address = segmentCommand->vmaddr;
                    *seg_size    = segmentCommand->vmsize;
                    LOG_DEBUG("Found __DATA segment at %p!", (void*)*segment_address);
                }
                break;
            }
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *segmentCommand = (struct segment_command_64 *)load_cmd;
                if (strncmp(segmentCommand->segname, segment_name, 16) == 0)
                {
                    *segment_address = segmentCommand->vmaddr;
                    *seg_size    = segmentCommand->vmsize;
                    LOG_DEBUG("Found __DATA segment at %p!", (void*)*segment_address);
                }
                break;
            }
        }
        // advance to next command
        load_cmd_addr += load_cmd->cmdsize;
    }
    return 0;
}
