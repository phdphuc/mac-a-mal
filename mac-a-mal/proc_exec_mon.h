//
//  proc_exec_mon.h
//  mac-a-mal
//
//  Created by vivami on 04/11/15.
//  Copyright © 2015 vivami. All rights reserved.
//

#ifndef proc_exec_mon_h
#define proc_exec_mon_h

#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/kern_event.h>
#include <libkern/libkern.h>
#include <mach/mach_types.h>

//static int processExec(kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

kern_return_t plug_kauth_listener(void);
kern_return_t unplug_kauth_listener(void);

#endif /* proc_exec_mon_h */
