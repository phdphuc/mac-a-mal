//  Legacy of grey-fox @ vivami on 04/11/15.
//

#include "my_data_definitions.h"
#include "sysent.h"
#include "hooker.h"
#include "proc_exec_mon.h"
#include <sys/param.h>
#include "kernel_control.h"
#include <IOKit/IOLib.h>

kern_return_t mac_a_mal_start(kmod_info_t * ki, void *d);
kern_return_t mac_a_mal_stop(kmod_info_t *ki, void *d);

/* Globals for syscall hooking */
void *_sysent;

kern_return_t mac_a_mal_start(kmod_info_t * ki, void *d)
{
    mach_vm_address_t kernel_base = 0;
    
    /* install the kernel control so we can enable/disable features */
    install_kern_control();
    
    
    if ((_sysent = find_sysent(&kernel_base)) == NULL) {
        return KERN_FAILURE;
    }
    hook_all_syscalls(_sysent);
    
    plug_kauth_listener();
    
    return KERN_SUCCESS;
}

kern_return_t mac_a_mal_stop(kmod_info_t *ki, void *d)
{
    /* This should be removed or add authentication method. There's no need for KEXT unload in live malware analysis running.*/
    
    // remove the kernel control socket
    if (remove_kern_control() != KERN_SUCCESS)
    {
        return KERN_FAILURE;
    }
    unhook_all_syscalls(_sysent);

    unplug_kauth_listener();
    
    /* This is super ugly, but waiting for all processes
       to finish using my hooked functions... Should be fixed
       semaphores.
     */
    IOSleep(20000);
    LOG_INFO("Exited.");
    return KERN_SUCCESS;
}
