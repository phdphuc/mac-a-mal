//
//  kernel_control.c
//  Legacy from fG! - reverser@put.as - http://reverse.put.as
//
//  Created by admin on 5/30/17.
//  Copyright © 2017 phdphuc. All rights reserved.
//  The funny thing: here's no authentication!!!

#include "kernel_control.h"

#include <sys/conf.h>
#include <sys/kernel.h>
#include <string.h>
#include <sys/systm.h>
#include <stdbool.h>
#include <sys/param.h>
#include <stdint.h>
#include <sys/kern_control.h>

#include "data.h"
#include "my_data_definitions.h"
#include "sysent.h"
#include <IOKit/IOLib.h>

// local globals
static int g_max_clients=-1;

static kern_ctl_ref g_ctl_ref[MAX_SOCKET];

static boolean_t g_kern_ctl_registered = FALSE;
int g_connection_to_userland;

char set_procname[256]={0};
int state=SLEEP;

pid_t trace_pid=-1;
static lck_grp_t* gLockGroup = NULL;         // our lock group
static lck_mtx_t* gLock = NULL;              // concruency management for accessing global data

static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo);
static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo);
static int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);

#pragma mark Kernel Control struct and handler functions

// described at Network Kernel Extensions Programming Guide
static struct kern_ctl_reg g_ctl_reg[MAX_SOCKET] = {
    BUNDLE_ID,            /* use a reverse dns name which includes a name unique to your comany */
    0,				   	  /* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
    0,					  /* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
    0,                    /* no privileged access required to access this filter */
    0,					  /* use default send size buffer */
    0,                    /* Override receive buffer size */
    ctl_connect,		  /* Called when a connection request is accepted */
    ctl_disconnect,		  /* called when a connection becomes disconnected */
    NULL,				  /* ctl_send_func - handles data sent from the client to kernel control - not implemented */
    ctl_set,			  /* called when the user process makes the setsockopt call */
    NULL			 	  /* called when the user process makes the getsockopt call */
};

static struct kcontrol_info
{
    int max_clients;
    kern_ctl_ref ctl_ref;
    u_int32_t client_unit;
    kern_ctl_ref client_ctl_ref;
    boolean_t kern_ctl_registered;
} g_kcontrol[MAX_SOCKET];

#pragma mark The start and stop functions

kern_return_t
install_kern_control(void)
{
    errno_t error = 0;
    gLockGroup = lck_grp_alloc_init(BUNDLE_ID, LCK_GRP_ATTR_NULL);
    if (!gLockGroup) {
        LOG_ERROR("Failed to alloc lock group \n");
        return KERN_FAILURE;
    }
    gLock = lck_mtx_alloc_init(gLockGroup, LCK_ATTR_NULL);
    if (!gLock) {
        LOG_ERROR("Failed to alloc config mutex \n");
        return KERN_FAILURE;
    }
    
    // register the kernel control
    int i = 0;
    char name[20] = {0};
    for (i=0;i<MAX_SOCKET;i++){
        snprintf(name,20, "%s%d", BUNDLE_ID,i);
        strncpy(g_ctl_reg[i].ctl_name, name, 20);
        g_ctl_reg[i].ctl_id = 0;
        g_ctl_reg[i].ctl_unit = 0;
        g_ctl_reg[i].ctl_flags = 0;
        g_ctl_reg[i].ctl_sendsize = 0;
        g_ctl_reg[i].ctl_recvsize = 0;
        g_ctl_reg[i].ctl_connect = ctl_connect;
        g_ctl_reg[i].ctl_disconnect = ctl_disconnect;
        g_ctl_reg[i].ctl_send = NULL;
        g_ctl_reg[i].ctl_setopt = ctl_set;
        g_ctl_reg[i].ctl_getopt = NULL;
        error = ctl_register(&g_ctl_reg[i], &g_ctl_ref[i]);
    }
    
    if (error == 0)
    {
        g_kern_ctl_registered = TRUE;
        LOG_DEBUG("Onyx kernel control installed successfully!");
        return KERN_SUCCESS;
    }
    else
    {
        LOG_ERROR("Failed to install Onyx kernel control!");
        return KERN_FAILURE;
    }
}

kern_return_t
remove_kern_control(void)
{
    errno_t error = 0;
    // remove kernel control
    error = ctl_deregister(g_ctl_ref);
    switch (error)
    {
        case 0:
        {
            return KERN_SUCCESS;
        }
        case EINVAL:
        {
            LOG_ERROR("The kernel control reference is invalid.");
            return KERN_FAILURE;
        }
        case EBUSY:
        {
            LOG_ERROR("The kernel control still has clients attached. Please disconnect them first!");
            return KERN_FAILURE;
        }
        default:
            return KERN_FAILURE;
    }
}

#pragma mark Kernel Control handler functions

/*
 * called when a client connects to the socket
 * we need to store some info to use later
 */
static int
ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
{
    lck_mtx_lock(gLock);
    // we only accept a single client
    if (g_max_clients > MAX_SOCKET-1)
    {
        return EBUSY;
    }
    g_max_clients++;
    
    g_kcontrol[g_max_clients].max_clients = g_max_clients;
    // store the unit id and ctl_ref of the client that connected
    // we will need these to queue data to userland
    g_kcontrol[g_max_clients].client_unit = sac->sc_unit;
    g_kcontrol[g_max_clients].client_ctl_ref = ctl_ref;
    if ( g_max_clients == MAX_SOCKET-1) g_connection_to_userland = 1;
    lck_mtx_unlock(gLock);
    return 0;
}

/*
 * and when client disconnects
 */
static errno_t
ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
{
    lck_mtx_lock(gLock);

    // reset some vars
    g_kcontrol[g_max_clients].max_clients = 0;
    g_kcontrol[g_max_clients].client_unit = 0;
    g_kcontrol[g_max_clients].client_ctl_ref = NULL;
    g_connection_to_userland = 0;
    state = SLEEP;
    memset(trackpid, 0, sizeof trackpid);
    lck_mtx_unlock(gLock);
    
    return 0;
}

/*
 * send data from userland to kernel
 * this is how userland apps adds and removes apps to be suspended
 */
static int
ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
    int error = 0;
    if (len == 0 || data == NULL)
    {
        LOG_ERROR("Invalid data to command.");
        return EINVAL;
    }
    switch (opt) {
        case 1:
            strncpy(set_procname, data, 256);
            printf("Tracing %s\n", set_procname);
            state = RUN;
            break;
        case 2:
            trace_pid =  (pid_t)strtol(data, (char **)NULL, 10);
            printf("PID %d %s", trace_pid, pid_run(trace_pid) ? "running": "");
            
            
        default:
            break;
    }
    

    return error;
}

kern_return_t
send_message(char* p)
{
    errno_t error = 0;
    lck_mtx_lock(gLock);
    if (g_max_clients<0 || g_max_clients>=MAX_SOCKET) g_max_clients=0;
    if (g_kcontrol[g_max_clients].client_ctl_ref == NULL)
    {
        LOG_ERROR("No client reference available. %d", g_max_clients);
        lck_mtx_unlock(gLock);
        return KERN_FAILURE;
    }
    size_t test = 0;
    ctl_getenqueuespace(g_kcontrol[g_max_clients].client_ctl_ref, g_kcontrol[g_max_clients].client_unit, &test);
    if (test<=MAX_SOCKET_LEN){

        if ( g_max_clients >=MAX_SOCKET -1 ) g_max_clients = 0;
            else g_max_clients++;
            ctl_getenqueuespace(g_kcontrol[g_max_clients].client_ctl_ref, g_kcontrol[g_max_clients].client_unit, &test);

    }
    error = ctl_enqueuedata(g_kcontrol[g_max_clients].client_ctl_ref, g_kcontrol[g_max_clients].client_unit, p, MAX_SOCKET_LEN, CTL_DATA_EOR);
    if (error)
    {
        ctl_getenqueuespace(g_kcontrol[g_max_clients].client_ctl_ref, g_kcontrol[g_max_clients].client_unit, &test);
        LOG_ERROR("ctl_enqueuedata failed with error: %d %ld %d", error, test, g_max_clients);
//Never giveup        g_connection_to_userland = 0;
//Continue        g_kcontrol.client_unit = 0;
    }
    lck_mtx_unlock(gLock);
    return error;
}

bool pid_run(int pid){
    proc_t proc;
    proc = proc_find(pid);
    if(proc){
        proc_rele(proc);
        return true;
    }
    else return false;
}
