//
//  main.c
//  grey-cuckoo
//
//  Created by admin on 5/30/17.
//  Copyright © 2017 admin. All rights reserved.
//


#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <sys/sys_domain.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/i386/thread_status.h>
#include <mach/mach_vm.h>

#include "data.h"

static int g_socket = -1;

#define MAXLEN 4098
#define MAXARG 512

//static void SignalHandler(int sigraised) {
//#if DEBUG
//    printf("\nInterrupted - %d\n", sigraised); // note - printf is unsupported function call from a signal handler
//#endif
//    if (g_socket > 0) {
//#if DEBUG
//        printf("closing socket %d\n", gSocket); // note - printf is an unsupported function call from a signal handler
//#endif
//        close (g_socket);
//    }
//    
//    // exit(0) should not be called from a signal handler.  Use _exit(0) instead
//    _exit(0);
//}

int
connect_to_kernel(void)
{
    struct sockaddr_ctl sc = {0};
    struct ctl_info ctl_info = {0};
    int ret = 0;
    
    g_socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (g_socket < 0)
    {
        printf("[ERROR] Failed to create socket!\n");
        exit(1);
    }
    // the control ID is dynamically generated so we must obtain sc_id using ioctl
    memset(&ctl_info, 0, sizeof(ctl_info));
    strncpy(ctl_info.ctl_name, BUNDLE_ID, MAX_KCTL_NAME);
    ctl_info.ctl_name[MAX_KCTL_NAME-1] = '\0';
    if (ioctl(g_socket, CTLIOCGINFO, &ctl_info) == -1)
    {
        printf("[ERROR] ioctl CTLIOCGINFO failed!\n");
        exit(1);
    }
#if DEBUG
    printf("[DEBUG] ctl_id: 0x%x for ctl_name: %s\n", ctl_info.ctl_id, ctl_info.ctl_name);
#endif
    
    bzero(&sc, sizeof(struct sockaddr_ctl));
    sc.sc_len = sizeof(struct sockaddr_ctl);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = ctl_info.ctl_id;
    sc.sc_unit = 0;
    
    ret = connect(g_socket, (struct sockaddr*)&sc, sizeof(sc));
    if (ret)
    {
        printf("[ERROR] Connect failed!\n");
        exit(1);
    }
    return 0;
}

void
print_me
int main(int argc, const char * argv[])
{
    if (connect_to_kernel())
    {
        printf("[ERROR] Can't connect to kernel control socket!\n");
        exit(1);
    }
    
    return 0;
}
