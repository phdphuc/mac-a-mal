//
//  proc_exec_mon.c
//  Legacy of grey-fox @ vivami on 04/11/15.
//
//  Implements KAuth listeners for Vnode scope and File operation scope:
//  Monitor WRITE operation on file path
//  Monitor EXEC opearation on a file -> create a pid trace based on specified proc name. It doesn't include fork/vfork.
//  For pid trace, see more in hook.c


#include "proc_exec_mon.h"
#include "my_data_definitions.h"
#include <IOKit/IOLib.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <kern/assert.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSMalloc.h>
#include <kern/clock.h>

#include "data.h"
#include "kernel_control.h"

kauth_listener_t kauthListener_file_op = NULL;
kauth_listener_t kauthListener_vnode = NULL;

int open_spawn = NO_TRACE_OPEN_SPAWN;

static OSMallocTag  gMallocTag = NULL;
enum {
    kActionStringMaxLength = 16384
};

struct VnodeActionInfo {
    kauth_action_t      fMask;                  // only one bit should be set
    const char *        fOpNameFile;            // descriptive name of the bit for files
    const char *        fOpNameDir;             // descriptive name of the bit for directories
};
typedef struct VnodeActionInfo VnodeActionInfo;
static SInt32 gActivationCount = 0;
static const char * gPrefix = NULL;         // points into gConfiguration, so doesn't need to be freed
extern int g_connection_to_userland;
bool trackpid[99999] = {0};
bool trackglobal = true;
#define kVnodeActionInfoCount (sizeof(kVnodeActionInfo) / sizeof(*kVnodeActionInfo))
#define VNODE_ACTION(action)                        { KAUTH_VNODE_ ## action,     #action,     NULL       }
#define VNODE_ACTION_FILEDIR(actionFile, actionDir) { KAUTH_VNODE_ ## actionFile, #actionFile, #actionDir }

// kVnodeActionInfo is a table of all the known action bits and their human readable names.
static const VnodeActionInfo kVnodeActionInfo[] = {
    VNODE_ACTION_FILEDIR(READ_DATA,   LIST_DIRECTORY),
    VNODE_ACTION_FILEDIR(WRITE_DATA,  ADD_FILE),
    VNODE_ACTION_FILEDIR(EXECUTE,     SEARCH),
    VNODE_ACTION(DELETE),
    VNODE_ACTION_FILEDIR(APPEND_DATA, ADD_SUBDIRECTORY),
    VNODE_ACTION(DELETE_CHILD),
    VNODE_ACTION(READ_ATTRIBUTES),
    VNODE_ACTION(WRITE_ATTRIBUTES),
    VNODE_ACTION(READ_EXTATTRIBUTES),
    VNODE_ACTION(WRITE_EXTATTRIBUTES),
    VNODE_ACTION(READ_SECURITY),
    VNODE_ACTION(WRITE_SECURITY),
    VNODE_ACTION(TAKE_OWNERSHIP),
    VNODE_ACTION(SYNCHRONIZE),
    VNODE_ACTION(LINKTARGET),
    VNODE_ACTION(CHECKIMMUTABLE),
    VNODE_ACTION(ACCESS),
    VNODE_ACTION(NOIMMUTABLE)
};


char* inString(char *haystack, char *needle)
{
    char c, sc;
    size_t len;
    
    if ((c = * needle ++) != 0) {
        len = strlen(needle);
        do {
            do {
                if ((sc = *haystack++) == 0) return (NULL);
            }
            while (sc != c);
        }
        while (strncmp(haystack, needle, len) != 0);
        haystack--;
    }
    return ((char *) haystack);
}

/* Creates VNODE action from an action bit flag. Code by Apple Inc. */
static int CreateVnodeActionString(kauth_action_t  action,
                                   boolean_t       isDir,
                                   char **         actionStrPtr,
                                   size_t *        actionStrBufSizePtr
                                   ) {
    int             err;
    enum { kCalcLen, kCreateString } pass;
    kauth_action_t  actionsLeft;
    unsigned int    infoIndex;
    size_t          actionStrLen = 0;
    size_t          actionStrSize;
    char *          actionStr;
    
    assert( actionStrPtr != NULL);
    assert(*actionStrPtr != NULL);
    assert( actionStrBufSizePtr != NULL);
    
    err = 0;
    
    actionStr = NULL;
    actionStrSize = 0;
    for (pass = kCalcLen; pass <= kCreateString; pass++) {
        actionsLeft = action;
        infoIndex = 0;
        actionStrLen = 0;
        while ( (actionsLeft != 0) && (infoIndex < kVnodeActionInfoCount) ) {
            if ( actionsLeft & kVnodeActionInfo[infoIndex].fMask ) {
                const char * thisStr;
                size_t       thisStrLen;
                if ( isDir && (kVnodeActionInfo[infoIndex].fOpNameDir != NULL) )
                    thisStr = kVnodeActionInfo[infoIndex].fOpNameDir;
                else
                    thisStr = kVnodeActionInfo[infoIndex].fOpNameFile;
                thisStrLen = strlen(thisStr);
                if (actionStr != NULL) {
                    memcpy(&actionStr[actionStrLen], thisStr, thisStrLen);
                }
                actionStrLen += thisStrLen;
                actionsLeft &= ~kVnodeActionInfo[infoIndex].fMask;
                if (actionsLeft != 0) {
                    if (actionStr != NULL) {
                        actionStr[actionStrLen] = '|';
                    }
                    actionStrLen += 1;
                }
            }
            infoIndex += 1;
        }
        if (actionsLeft != 0) {
            if (actionStr != NULL) {
                snprintf(&actionStr[actionStrLen], actionStrSize - actionStrLen, "0x%08x", actionsLeft);
            }
            actionStrLen += 10;         // strlen("0x") + 8 chars of hex
        }
        if (pass == kCalcLen) {
            if (actionStrLen > kActionStringMaxLength)
                err = ENOBUFS;
            else {
                actionStrSize = actionStrLen + 1;
                actionStr = OSMalloc( (uint32_t) actionStrSize, gMallocTag);
                if (actionStr == NULL)
                    err = ENOMEM;
            }
        } else
            actionStr[actionStrLen] = 0;
        if (err != 0)
            break;
    }
    *actionStrPtr        = actionStr;
    *actionStrBufSizePtr = actionStrLen + 1;
    assert( (err == 0) == (*actionStrPtr != NULL) );
    return err;
}

static int CreateVnodePath(vnode_t vp, char **vpPathPtr)
{
    int             err;
    int             pathLen;
    
    assert( vpPathPtr != NULL);
    assert(*vpPathPtr == NULL);
    
    err = 0;
    if (vp != NULL) {
        *vpPathPtr = OSMalloc(MAXPATHLEN, gMallocTag);
        if (*vpPathPtr == NULL) {
            err = ENOMEM;
        }
        if (err == 0) {
            pathLen = MAXPATHLEN;
            err = vn_getpath(vp, *vpPathPtr, &pathLen);
        }
    }
    
    return err;
}

int isRoot(long uid) {
    return (uid == 0) ? 1 : 0;
}

/* KAuth file operations scope listener (monitors SYS_execve). */
static int FileOpScopeListener(kauth_cred_t credential, void* idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3) {
    
    char path[MAXPATHLEN] = {0};
    uid_t uid = -1;
    pid_t pid = -1;
    pid_t ppid = -1;
    
    if(KAUTH_FILEOP_EXEC != action ){
        goto bail;
    }
    strncpy(path, (const char*)arg1, MAXPATHLEN-1);
    uid = kauth_getuid();
    pid = proc_selfpid();
    ppid = proc_selfppid();
    char procname[MAXPATHLEN+1] = {0};
    proc_name(pid, procname, MAXPATHLEN+1);
    unsigned long long timestamp =0 ;
    clock_get_uptime(&timestamp);
    timestamp = timestamp/ 1000000;
    if ((state == RUN || state == TRACE) && strncmp(path, set_procname, strlen(path)) == 0) {
        if (strncmp(path, "/usr/bin/open", strlen(path)) == 0) open_spawn = TRACE_OPEN_SPAWN;
        trackpid[pid] = true;
        LOG_INFO("++ %d\n", pid);
        LOG_INFO("+++ %s %s\n", path, set_procname);
        state = TRACE;
    }
    else
    {
        LOG_INFO("+++ %s %s %d %d\n", path, set_procname, state, open_spawn);
    }

    SEND_INFO(-1, "{\"sc\":\"NEW_PROCESS\",\"a\":[\"%s\"],\"r\":0,\"t\":%lu, \"p\":%d, \"pp\":%d, \"u\":%d,\"pn\":\"%s\"}\n",
           path,
           timestamp,
           pid,
           ppid,
           uid,
           procname);
    
bail:
    return KAUTH_RESULT_DEFER;
}

/* KAuth file operations scope listener. Monitors SYS_write. Mainly Apple Inc. code. */
static int VnodeScopeListener(
                              kauth_cred_t    credential,
                              void *          idata,
                              kauth_action_t  action,
                              uintptr_t       arg0,
                              uintptr_t       arg1,
                              uintptr_t       arg2,
                              uintptr_t       arg3
                              ) {
#pragma unused(credential)
#pragma unused(idata)
#pragma unused(arg3)
    int             err;
    vfs_context_t   context;
    vnode_t         vp;
    vnode_t         dvp;
    char *          vpPath;
    char *          dvpPath;
    boolean_t       isDir;
    char *          actionStr;
    size_t          actionStrBufSize;
    char            procname[MAXPATHLEN+1] = {0};
    actionStrBufSize = 0;
    
    (void) OSIncrementAtomic(&gActivationCount);
    
    context = (vfs_context_t) arg0;
    vp      = (vnode_t) arg1;
    dvp     = (vnode_t) arg2;
    
    vpPath = NULL;
    dvpPath = NULL;
    actionStr = NULL;
    
    err = CreateVnodePath(vp, &vpPath);
    
    if (err == 0) {
        err = CreateVnodePath(dvp, &dvpPath);
    }
    if (err == 0) {
        if (vp != NULL) {
            isDir = ( vnode_vtype(vp) == VDIR );
        } else {
            isDir = FALSE;
        }
        err = CreateVnodeActionString(action, isDir, &actionStr, &actionStrBufSize);
    }
    pid_t pid = proc_selfpid();
    pid_t ppid = proc_selfppid();
    proc_name(pid, procname, MAXPATHLEN+1);
    
    if (err == 0) {
        if (  (gPrefix == NULL)
            || (  ( (vpPath != NULL)  && strprefix(vpPath, gPrefix) )
                || ( (dvpPath != NULL) && strprefix(dvpPath, gPrefix) )
                )
            ) {
            // We don't want SYS_writes from Console and syslogd (causing deadlock)
            if ((inString(actionStr, "WRITE") != NULL) && (strcmp(procname, "Console") != 0) && (strcmp(procname, "syslogd") != 0) && (strcmp(procname, "system_installd") != 0)) {
                unsigned long long timestamp =0 ;
                clock_get_uptime(&timestamp);
                timestamp = timestamp/ 1000000;
                SEND_INFO(-1, "{\"sc\":\"WRITE\",\"a\":[\"%s\"],\"r\":0,\"t\":%lu, \"p\":%d, \"pp\":%d, \"u\":%d,\"pn\":\"%s\"}\n",
                          (vpPath  != NULL) ?  vpPath : "<null>",
                          timestamp,
                          pid,
                          ppid,
                          kauth_cred_getuid(vfs_context_ucred(context)),
                          procname);
                
                
//                struct userland_event event = {0};
//
//                if (g_connection_to_userland){
//                    event.active=1;
//                    event.pid = pid;
//                    event.ppid = ppid;
//                    event.uid = 4;
//                    proc_name(ppid, event.parent_name, sizeof(event.parent_name));
//                    send_message(&event);
//                }
//                kprintf("[PHAMOOK] %u:%u:%lu,%u; %s; %d; %d; SYS_write; %d; %s\n",
//                       hours,
//                       mins,
//                       secs,
//                       microsecs,
//                       procname,
//                       pid,
//                       ppid,
//                       isRoot(kauth_cred_getuid(vfs_context_ucred(context))),
//                       (vpPath  != NULL) ?  vpPath : "<null>");
            }
           
        }
    }
    
    
    if (actionStr != NULL) {
        OSFree(actionStr, (uint32_t) actionStrBufSize, gMallocTag);
    }
    if (vpPath != NULL) {
        OSFree(vpPath, MAXPATHLEN, gMallocTag);
    }
    if (dvpPath != NULL) {
        OSFree(dvpPath, MAXPATHLEN, gMallocTag);
    }
    
    (void) OSDecrementAtomic(&gActivationCount);
    
    return KAUTH_RESULT_DEFER;
}

/* install listeners */
kern_return_t plug_kauth_listener(void) {
    kern_return_t   err;
    gMallocTag = OSMalloc_Tagalloc("mac-a-mal", OSMT_DEFAULT);
    if (gMallocTag == NULL) {
        err = KERN_FAILURE;
    }


    kauthListener_file_op = kauth_listen_scope(KAUTH_SCOPE_FILEOP, &FileOpScopeListener, NULL);
    if (kauthListener_file_op == NULL) {
        LOG_ERROR("Failed to plug KAuth KAUTH_SCOPE_FILEOP listener.");
        return KERN_FAILURE;
    }
    LOG_INFO("Plugged KAUTH_SCOPE_FILEOP listener.");
    kauthListener_vnode = kauth_listen_scope(KAUTH_SCOPE_VNODE, &VnodeScopeListener, NULL);
    if (kauthListener_vnode == NULL) {
        LOG_ERROR("Failed to plug KAuth KAUTH_SCOPE_VNODE listener.");
        return KERN_FAILURE;
    }
    LOG_INFO("Plugged KAUTH_SCOPE_VNODE listener.");
    ;

    return KERN_SUCCESS;
}

/* uninstall listeners */
kern_return_t unplug_kauth_listener(void) {
    if(kauthListener_file_op != NULL) {
        kauth_unlisten_scope(kauthListener_file_op);
        kauthListener_file_op = NULL;
    }
    if(kauthListener_vnode != NULL) {
        kauth_unlisten_scope(kauthListener_vnode);
        kauthListener_vnode = NULL;
    }
    if (gMallocTag != NULL) {
        OSMalloc_Tagfree(gMallocTag);
        gMallocTag = NULL;
    }
    return KERN_SUCCESS;
}
