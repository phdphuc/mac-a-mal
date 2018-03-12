//
//  hooker.c
//  Based on vivami 2015 - mac-a-mal legacy
//
//  Hooks all the relevant system calls and logs them to system.log for later analysis.
//
//  Pham Duy Phuc 2017:
//  Updated working on newest MacOS version.
//  Only support x64 from now.
//  Trace pids
//  No logging on some boring Apple processes, and grey-cuckoo itself
//  TODO: there is a mess when hooking ENTRY & RETURN SYSCALL
//  Need improvements : extract fildes args; Randomize hooking process name (in this case: grey-cuckoo); Better way to know when all traced pids are terminated, etc.
//  TODO: Hook table & args should be able to generated from JSON file from userspace instead. It will make the module much customizable.
//  TODO: Hook unlink() should move the file tobe deleted to /tmp/ before deleting and dump it later.
//  Print argv[] is tricky from execve & posix_spawn, not sure if there's any other solution.
//  SEND_INFO() to send logs through kernel-user socket communication.
//  Lots of them are generated automatically. Reference from Dtruss script.
//  Return UID spawned a process rather than real username; this can be resolved at user-space through /etc/passwd or whatever.


#include "cpu_protections.h"
#include "hooker.h"
#include <sys/syslimits.h>
#include "proc.h"

#include <kern/clock.h>
#include <libkern/OSMalloc.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "data.h"
#include <libkern/libkern.h>

void hook_syscall(void *sysent_addr, uint32_t syscall);
void unhook_syscall(void *sysent_addr, uint32_t syscall);

clock_sec_t lastsec=0;

typedef int (*kern_f)(struct proc *, struct args *, int *);

/* Array of pointers to original syscall functions. Saved to restore before leaving the kernel. */
static kern_f kernel_functions[SYS_MAXSYSCALL+1] = {0};

/* Array of pointers to our own hook functions. The NULL pointers are syscalls we don't hook (to reduce
 * verbosity of the dataset), or syscalls that are deprecated.
 * Remove munmap - not interesting
 *
 */
static int (*hook_functions[SYS_MAXSYSCALL+1]) = {NULL, hook_exit, hook_fork, hook_read, hook_write, hook_open, hook_close, NULL, NULL, hook_link, hook_unlink, NULL, hook_chdir, NULL, hook_mknod, hook_chmod, hook_chown, NULL, hook_getfsstat, NULL, NULL, NULL, NULL, hook_setuid, NULL, NULL, hook_ptrace, hook_recvmsg,hook_sendmsg,hook_recvfrom,hook_accept,hook_getpeername,hook_getsockname, hook_access, hook_chflags, hook_fchflags, NULL, hook_kill, NULL, hook_getppid, NULL, hook_dup,
    /*hook_pipe*/ NULL,
    hook_getegid, NULL, NULL, NULL/*hook_sigaction*/, NULL, NULL, hook_getlogin, hook_setlogin, hook_acct, hook_sigpending, NULL, hook_ioctl, hook_reboot, hook_revoke, hook_symlink, hook_readlink, hook_execve, hook_umask, hook_chroot, NULL, NULL, NULL, hook_msync, hook_vfork, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL /*hook_munmap too aggresive*/,
    hook_mprotect, NULL, NULL, NULL, hook_mincore, hook_getgroups, hook_setgroups, hook_getpgrp, hook_setpgid, NULL, NULL, hook_swapon, hook_getitimer, NULL, NULL, hook_getdtablesize, hook_dup2, NULL, hook_fcntl, NULL, NULL, NULL, hook_setpriority, hook_socket, hook_connect, NULL, hook_getpriority, NULL, NULL, NULL, hook_bind, hook_setsockopt, hook_listen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, hook_getsockopt, NULL, hook_readv, hook_writev, hook_settimeofday, hook_fchown, hook_fchmod, NULL, hook_setreuid, hook_setregid, hook_rename, NULL, NULL, hook_flock, hook_mkfifo, hook_sendto, hook_shutdown, hook_socketpair, hook_mkdir, hook_rmdir, hook_utimes, hook_futimes, NULL, NULL, hook_gethostuuid, NULL, NULL, NULL, NULL, hook_setsid, NULL, NULL, NULL, hook_getpgid, hook_setprivexec, NULL, hook_pwrite, hook_nfssvc, NULL, hook_statfs, hook_fstatfs, hook_unmount, NULL, hook_getfh, NULL, NULL, NULL, hook_quotactl, NULL, hook_mount, NULL, NULL, NULL, NULL, NULL, hook_waitid, NULL, NULL, NULL, NULL, NULL, NULL, hook_kdebug_trace, hook_setgid, hook_setegid, hook_seteuid, NULL, hook_chud, NULL, hook_fdatasync, hook_stat, hook_fstat, hook_lstat, hook_pathconf, hook_fpathconf, NULL, hook_getrlimit, hook_setrlimit, hook_getdirentries, NULL, NULL, NULL, hook_truncate, hook_ftruncate, hook___sysctl, hook_mlock, hook_munlock, hook_undelete, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, hook_setattrlist, hook_getdirentriesattr, hook_exchangedata, NULL, hook_searchfs, hook_delete, hook_copyfile, hook_fgetattrlist, hook_fsetattrlist, hook_poll, hook_watchevent, hook_waitevent, hook_modwatch, NULL, hook_fgetxattr, hook_setxattr, hook_fsetxattr, hook_removexattr, hook_fremovexattr, hook_listxattr, hook_flistxattr, hook_fsctl, hook_initgroups, hook_posix_spawn, hook_ffsctl, NULL, hook_nfsclnt, NULL, NULL, hook_minherit, hook_semsys, hook_msgsys, hook_shmsys, hook_semctl, hook_semget, hook_semop, NULL, hook_msgctl, hook_msgget, hook_msgsnd, hook_msgrcv, hook_shmat, hook_shmctl, hook_shmdt, hook_shmget, hook_shm_open, hook_shm_unlink, NULL, hook_sem_close, hook_sem_unlink, hook_sem_wait, hook_sem_trywait, hook_sem_post, hook_sysctlbyname, hook_sem_init, hook_sem_destroy, hook_open_extended, hook_umask_extended, hook_stat_extended, hook_lstat_extended, hook_fstat_extended, hook_chmod_extended, hook_fchmod_extended, hook_access_extended, hook_settid, NULL, hook_setsgroups, hook_getsgroups, hook_setwgroups, hook_getwgroups, hook_mkfifo_extended, hook_mkdir_extended, hook_identitysvc, hook_shared_region_check_np, NULL, hook_vm_pressure_monitor, hook_psynch_rw_longrdlock, hook_psynch_rw_yieldwrlock, hook_psynch_rw_downgrade, hook_psynch_rw_upgrade, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, hook_psynch_rw_unlock2, hook_getsid, hook_settid_with_pid, hook_psynch_cvclrprepost, hook_aio_fsync, hook_aio_return, hook_aio_suspend, hook_aio_cancel, hook_aio_error, hook_aio_read, hook_aio_write, hook_lio_listio, NULL, NULL, NULL, hook_mlockall, hook_munlockall, NULL, NULL, hook___pthread_kill, NULL, hook___sigwait, NULL, hook___pthread_markcancel, NULL, NULL, NULL, NULL, hook_sendfile, hook_stat64, NULL, NULL, hook_stat64_extended, hook_lstat64_extended, hook_fstat64_extended, NULL, NULL, NULL, NULL, NULL, NULL, hook_audit, hook_auditon, NULL, hook_getauid, hook_setauid, NULL, NULL, NULL, hook_setaudit_addr, hook_auditctl, hook_bsdthread_create, NULL, NULL, NULL, hook_lchown, hook_stack_snapshot, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, hook___mac_execve,
        NULL /*hook___mac_syscall*/,
        hook___mac_get_file, hook___mac_set_file, hook___mac_get_link, hook___mac_set_link, hook___mac_get_proc, hook___mac_set_proc, hook___mac_get_fd, hook___mac_set_fd, hook___mac_get_pid, hook___mac_get_lcid, hook___mac_get_lctx, hook___mac_set_lctx, hook_pselect, hook_pselect_nocancel, hook_read_nocancel,hook_write_nocancel,hook_open_nocancel,hook_close_nocancel, hook_wait4_nocancel, hook_recvmsg_nocancel, hook_sendmsg_nocancel, hook_recvfrom_nocancel, hook_accept_nocancel, hook_msync_nocancel, hook_fcntl_nocancel, hook_select_nocancel, hook_fsync_nocancel, hook_connect_nocancel, hook_sigsuspend_nocancel, hook_readv_nocancel, hook_writev_nocancel, hook_sendto_nocancel, hook_pread_nocancel, hook_pwrite_nocancel, hook_waitid_nocancel, hook_poll_nocancel, hook_msgsnd_nocancel, hook_msgrcv_nocancel, hook_sem_wait_nocancel, hook_aio_suspend_nocancel, hook___sigwait_nocancel, hook___semwait_signal_nocancel, hook___mac_mount, hook___mac_get_mount, hook___mac_getfsstat, NULL, hook_audit_session_self, hook_audit_session_join, hook_fileport_makeport, hook_fileport_makefd, hook_audit_session_port, hook_pid_suspend, hook_pid_resume, NULL, NULL, NULL, hook_shared_region_map_and_slide_np, hook_kas_info, NULL,hook_guarded_open_np,NULL,NULL,NULL,NULL,NULL,hook_connectx,hook_disconnectx,hook_peeloff,hook_socket_delegate,hook_telemetry,hook_proc_uuid_policy,hook_memorystatus_get_level,hook_system_override,hook_vfs_purge,hook_sfi_ctl, hook_sfi_pidctl,hook_coalition,hook_coalition_info,hook_necp_match_policy,hook_getattrlistbulk,hook_clonefileat,hook_openat,hook_openat_nocancel,hook_renameat,hook_faccessat,hook_fchmodat,hook_fchownat,hook_fstatat,hook_fstatat64,hook_linkat,hook_unlinkat,hook_readlinkat,hook_symlinkat,hook_mkdirat,hook_getattrlistat,hook_proc_trace_log,hook_bsdthread_ctl,hook_openbyid_np,hook_recvmsg_x,hook_sendmsg_x,hook_thread_selfusage,
    /*check csrutil stuffs; lets hook in case it checks for SIP.*/hook_csrctl,
    NULL,NULL,NULL,NULL,hook_renameatx_np};
/*
 Auto full - generated
 static int (*hook_functions[SYS_MAXSYSCALL+1]) = {hook_syscall,hook_exit,hook_fork,hook_read,hook_write,hook_open,hook_close,hook_wait4,NULL,hook_link,hook_unlink,NULL,hook_chdir,hook_fchdir,hook_mknod,hook_chmod,hook_chown,NULL,hook_getfsstat,NULL,hook_getpid,NULL,NULL,hook_setuid,hook_getuid,hook_geteuid,hook_ptrace,hook_recvmsg,hook_sendmsg,hook_recvfrom,hook_accept,hook_getpeername,hook_getsockname,hook_access,hook_chflags,hook_fchflags,hook_sync,hook_kill,NULL,hook_getppid,NULL,hook_dup,hook_pipe,hook_getegid,NULL,NULL,hook_sigaction,hook_getgid,hook_sigprocmask,hook_getlogin,hook_setlogin,hook_acct,hook_sigpending,hook_sigaltstack,hook_ioctl,hook_reboot,hook_revoke,hook_symlink,hook_readlink,hook_execve,hook_umask,hook_chroot,NULL,NULL,NULL,hook_msync,hook_vfork,NULL,NULL,NULL,NULL,NULL,NULL,hook_munmap,hook_mprotect,hook_madvise,NULL,NULL,hook_mincore,hook_getgroups,hook_setgroups,hook_getpgrp,hook_setpgid,hook_setitimer,NULL,hook_swapon,hook_getitimer,NULL,NULL,hook_getdtablesize,hook_dup2,NULL,hook_fcntl,hook_select,NULL,hook_fsync,hook_setpriority,hook_socket,hook_connect,NULL,hook_getpriority,NULL,NULL,NULL,hook_bind,hook_setsockopt,hook_listen,NULL,NULL,NULL,NULL,hook_sigsuspend,NULL,NULL,NULL,NULL,hook_gettimeofday,hook_getrusage,hook_getsockopt,NULL,hook_readv,hook_writev,hook_settimeofday,hook_fchown,hook_fchmod,NULL,hook_setreuid,hook_setregid,hook_rename,NULL,NULL,hook_flock,hook_mkfifo,hook_sendto,hook_shutdown,hook_socketpair,hook_mkdir,hook_rmdir,hook_utimes,hook_futimes,hook_adjtime,NULL,hook_gethostuuid,NULL,NULL,NULL,NULL,hook_setsid,NULL,NULL,NULL,hook_getpgid,hook_setprivexec,hook_pread,hook_pwrite,hook_nfssvc,NULL,hook_statfs,hook_fstatfs,hook_unmount,NULL,hook_getfh,NULL,NULL,NULL,hook_quotactl,NULL,hook_mount,NULL,hook_csops,hook_csops_audittoken,NULL,NULL,hook_waitid,NULL,NULL,NULL,hook_kdebug_typefilter,hook_kdebug_trace_string,hook_kdebug_trace64,hook_kdebug_trace,hook_setgid,hook_setegid,hook_seteuid,hook_sigreturn,hook_chud,NULL,hook_fdatasync,hook_stat,hook_fstat,hook_lstat,hook_pathconf,hook_fpathconf,NULL,hook_getrlimit,hook_setrlimit,hook_getdirentries,hook_mmap,NULL,hook_lseek,hook_truncate,hook_ftruncate,hook___sysctl,hook_mlock,hook_munlock,hook_undelete,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,hook_open_dprotected_np,NULL,NULL,NULL,hook_getattrlist,hook_setattrlist,hook_getdirentriesattr,hook_exchangedata,NULL,hook_searchfs,hook_delete,hook_copyfile,hook_fgetattrlist,hook_fsetattrlist,hook_poll,hook_watchevent,hook_waitevent,hook_modwatch,hook_getxattr,hook_fgetxattr,hook_setxattr,hook_fsetxattr,hook_removexattr,hook_fremovexattr,hook_listxattr,hook_flistxattr,hook_fsctl,hook_initgroups,hook_posix_spawn,hook_ffsctl,NULL,hook_nfsclnt,hook_fhopen,NULL,hook_minherit,hook_semsys,hook_msgsys,hook_shmsys,hook_semctl,hook_semget,hook_semop,NULL,hook_msgctl,hook_msgget,hook_msgsnd,hook_msgrcv,hook_shmat,hook_shmctl,hook_shmdt,hook_shmget,hook_shm_open,hook_shm_unlink,hook_sem_open,hook_sem_close,hook_sem_unlink,hook_sem_wait,hook_sem_trywait,hook_sem_post,hook_sysctlbyname,hook_sem_init,hook_sem_destroy,hook_open_extended,hook_umask_extended,hook_stat_extended,hook_lstat_extended,hook_fstat_extended,hook_chmod_extended,hook_fchmod_extended,hook_access_extended,hook_settid,hook_gettid,hook_setsgroups,hook_getsgroups,hook_setwgroups,hook_getwgroups,hook_mkfifo_extended,hook_mkdir_extended,hook_identitysvc,hook_shared_region_check_np,NULL,hook_vm_pressure_monitor,hook_psynch_rw_longrdlock,hook_psynch_rw_yieldwrlock,hook_psynch_rw_downgrade,hook_psynch_rw_upgrade,hook_psynch_mutexwait,hook_psynch_mutexdrop,hook_psynch_cvbroad,hook_psynch_cvsignal,hook_psynch_cvwait,hook_psynch_rw_rdlock,hook_psynch_rw_wrlock,hook_psynch_rw_unlock,hook_psynch_rw_unlock2,hook_getsid,hook_settid_with_pid,hook_psynch_cvclrprepost,hook_aio_fsync,hook_aio_return,hook_aio_suspend,hook_aio_cancel,hook_aio_error,hook_aio_read,hook_aio_write,hook_lio_listio,NULL,hook_iopolicysys,hook_process_policy,hook_mlockall,hook_munlockall,NULL,hook_issetugid,hook___pthread_kill,hook___pthread_sigmask,hook___sigwait,hook___disable_threadsignal,hook___pthread_markcancel,hook___pthread_canceled,hook___semwait_signal,NULL,hook_proc_info,hook_sendfile,hook_stat64,hook_fstat64,hook_lstat64,hook_stat64_extended,hook_lstat64_extended,hook_fstat64_extended,hook_getdirentries64,hook_statfs64,hook_fstatfs64,hook_getfsstat64,hook___pthread_chdir,hook___pthread_fchdir,hook_audit,hook_auditon,NULL,hook_getauid,hook_setauid,NULL,NULL,hook_getaudit_addr,hook_setaudit_addr,hook_auditctl,hook_bsdthread_create,hook_bsdthread_terminate,hook_kqueue,hook_kevent,hook_lchown,hook_stack_snapshot,hook_bsdthread_register,hook_workq_open,hook_workq_kernreturn,hook_kevent64,hook___old_semwait_signal,hook___old_semwait_signal_nocancel,hook_thread_selfid,hook_ledger,hook_kevent_qos,NULL,NULL,NULL,NULL,NULL,hook___mac_execve,hook___mac_syscall,hook___mac_get_file,hook___mac_set_file,hook___mac_get_link,hook___mac_set_link,hook___mac_get_proc,hook___mac_set_proc,hook___mac_get_fd,hook___mac_set_fd,hook___mac_get_pid,hook___mac_get_lcid,hook___mac_get_lctx,hook___mac_set_lctx,hook_pselect,hook_pselect_nocancel,hook_read_nocancel,hook_write_nocancel,hook_open_nocancel,hook_close_nocancel,hook_wait4_nocancel,hook_recvmsg_nocancel,hook_sendmsg_nocancel,hook_recvfrom_nocancel,hook_accept_nocancel,hook_msync_nocancel,hook_fcntl_nocancel,hook_select_nocancel,hook_fsync_nocancel,hook_connect_nocancel,hook_sigsuspend_nocancel,hook_readv_nocancel,hook_writev_nocancel,hook_sendto_nocancel,hook_pread_nocancel,hook_pwrite_nocancel,hook_waitid_nocancel,hook_poll_nocancel,hook_msgsnd_nocancel,hook_msgrcv_nocancel,hook_sem_wait_nocancel,hook_aio_suspend_nocancel,hook___sigwait_nocancel,hook___semwait_signal_nocancel,hook___mac_mount,hook___mac_get_mount,hook___mac_getfsstat,hook_fsgetpath,hook_audit_session_self,hook_audit_session_join,hook_fileport_makeport,hook_fileport_makefd,hook_audit_session_port,hook_pid_suspend,hook_pid_resume,hook_pid_hibernate,hook_pid_shutdown_sockets,NULL,hook_shared_region_map_and_slide_np,hook_kas_info,hook_memorystatus_control,hook_guarded_open_np,hook_guarded_close_np,hook_guarded_kqueue_np,hook_change_fdguard_np,hook_usrctl,hook_proc_rlimit_control,hook_connectx,hook_disconnectx,hook_peeloff,hook_socket_delegate,hook_telemetry,hook_proc_uuid_policy,hook_memorystatus_get_level,hook_system_override,hook_vfs_purge,hook_sfi_ctl,hook_sfi_pidctl,hook_coalition,hook_coalition_info,hook_necp_match_policy,hook_getattrlistbulk,hook_clonefileat,hook_openat,hook_openat_nocancel,hook_renameat,hook_faccessat,hook_fchmodat,hook_fchownat,hook_fstatat,hook_fstatat64,hook_linkat,hook_unlinkat,hook_readlinkat,hook_symlinkat,hook_mkdirat,hook_getattrlistat,hook_proc_trace_log,hook_bsdthread_ctl,hook_openbyid_np,hook_recvmsg_x,hook_sendmsg_x,hook_thread_selfusage,hook_csrctl,hook_guarded_open_dprotected_np,hook_guarded_write_np,hook_guarded_pwrite_np,hook_guarded_writev_np,hook_renameatx_np,hook_mremap_encrypted,hook_netagent_trigger,hook_stack_snapshot_with_config,hook_microstackshot,hook_grab_pgo_data,hook_persona,NULL,NULL,NULL,NULL,hook_work_interval_ctl,hook_getentropy,hook_necp_open,hook_necp_client_action,hook___nexus_open,hook___nexus_register,hook___nexus_deregister,hook___nexus_create,hook___nexus_destroy,hook___nexus_get_opt,hook___nexus_set_opt,hook___channel_open,hook___channel_get_info,hook___channel_sync,hook___channel_get_opt,hook___channel_set_opt,hook_ulock_wait,hook_ulock_wake,hook_fclonefileat,hook_fs_snapshot,NULL,hook_terminate_with_payload,hook_abort_with_payload,NULL};
 */

extern const int version_major;
static OSMallocTag  syscalloc = NULL;
kern_return_t hook_all_syscalls(void *sysent_addr) {
    syscalloc = OSMalloc_Tagalloc("sycalloc", OSMT_DEFAULT);
    enable_kernel_write();
    // SYS_MAXSYSCALL is the last syscall
    for (uint32_t i = SYS_fork; i <= SYS_MAXSYSCALL; i++) {
        hook_syscall(sysent_addr, i);
    }
    disable_kernel_write();
    return KERN_SUCCESS;
}

kern_return_t unhook_all_syscalls(void *sysent_addr) {
    if (syscalloc != NULL) {
        OSMalloc_Tagfree(syscalloc);
        syscalloc = NULL;
    }
    enable_kernel_write();
    for (uint32_t i = SYS_fork; i <= SYS_MAXSYSCALL; i++) {
        unhook_syscall(sysent_addr, i);
    }
    disable_kernel_write();
    return KERN_SUCCESS;
}

/* Replaces (based on relevant system call), the syscall function pointer to the original syscall function,
 with an implementation of my own (see bottom). Original pointer is stored in a buffer for unhooking. */
void hook_syscall(void *sysent_addr, uint32_t syscall) {
    switch (version_major) {
        case SIERRA:
        case EL_CAPITAN: {
            struct sysent_yosemite *sysent = (struct sysent_yosemite*)sysent_addr;
            if (hook_functions[syscall]) {
                kernel_functions[syscall] = (void*)sysent[syscall].sy_call;
                sysent[syscall].sy_call = (sy_call_t*)hook_functions[syscall];
                LOG_INFO("Hooked syscall no.: %d\n", syscall);
            }
            break;
        }
        case YOSEMITE: {
            struct sysent_yosemite *sysent = (struct sysent_yosemite*)sysent_addr;
            if (hook_functions[syscall] != NULL) {
                kernel_functions[syscall] = (void*)sysent[syscall].sy_call;
                sysent[syscall].sy_call = (sy_call_t*)hook_functions[syscall];
                LOG_INFO("Hooked syscall no.: %d\n", syscall);
            }
            break;
        }
        case MAVERICKS: {
            struct sysent_mavericks *sysent = (struct sysent_mavericks*)sysent_addr;
            if (hook_functions[syscall]) {
                kernel_functions[syscall] = (void*)sysent[syscall].sy_call;
                sysent[syscall].sy_call = (sy_call_t*)hook_functions[syscall];
                LOG_INFO("Hooked syscall no.: %d\n", syscall);
            }
            break;
        }
        default: {
            struct sysent *sysent = (struct sysent*)sysent_addr;
            if (hook_functions[syscall]) {
                kernel_functions[syscall] = (void*)sysent[syscall].sy_call;
                sysent[syscall].sy_call = (sy_call_t*)hook_functions[syscall];
                LOG_INFO("Hooked syscall no.: %d\n", syscall);
            }
            break;
        }
    }
}

/* Restores the original syscall function. */
void unhook_syscall(void *sysent_addr, uint32_t syscall) {
    switch (version_major) {
        case SIERRA:
        case EL_CAPITAN: {
            if (kernel_functions[syscall] != NULL) {
                struct sysent_yosemite *sysent = (struct sysent_yosemite*)sysent_addr;
                sysent[syscall].sy_call = (sy_call_t*)kernel_functions[syscall];
                LOG_INFO("Unhooked syscall %d\n", syscall);
            } else {
                LOG_INFO("Syscall %d was not hooked...\n", syscall);
            }
            break;
        }
        case YOSEMITE: {
            if (kernel_functions[syscall] != NULL) {
                struct sysent_yosemite *sysent = (struct sysent_yosemite*)sysent_addr;
                sysent[syscall].sy_call = (sy_call_t*)kernel_functions[syscall];
                LOG_INFO("Unhooked syscall %d\n", syscall);
            } else {
                LOG_INFO("Syscall %d was not hooked...\n", syscall);
            }
            break;
        }
        case MAVERICKS: {
            struct sysent_mavericks *sysent = (struct sysent_mavericks*)sysent_addr;
            if (kernel_functions[syscall] != NULL) {
                sysent[syscall].sy_call = (sy_call_t*)kernel_functions[syscall];
                LOG_INFO("Unhooked syscall %d\n", syscall);
            } else {
                LOG_INFO("Syscall %d was not hooked...\n", syscall);
            }
            break;
        }
        default: {
            struct sysent *sysent = (struct sysent*)sysent_addr;
            if (kernel_functions[syscall] != NULL) {
                sysent[syscall].sy_call = (sy_call_t*)kernel_functions[syscall];
                LOG_INFO("Unhooked syscall %d\n", syscall);
            } else {
                LOG_INFO("Syscall %d was not hooked...\n", syscall);
            }
            break;
        }
    }
}

/* Prevents deadlocks by checking if the process is not a call from syslogd or kernel. */
int32_t should_i_log_this( pid_t pid , char *processname) {
    
    return (pid != 0
            && (strcmp("syslogd", processname) != 0)
            && (strcmp("vmware-tools-dae", processname) != 0)
            && (strcmp("nsurlsessiond", processname) != 0)
            
            
            /*Phamous 22 May:
             This is an obvious evasion hole, we need to find another safe way to exclude this procname.
             */
            && (strcmp("Console", processname) != 0)
            && (strcmp("mac-a-mal", processname) != 0)
            && (strcmp("diagnosticd", processname) != 0) /*10.12*/
            && (strcmp("sharedfilelistd", processname) != 0) /*10.12*/
            
            ) ? 1 : 0;
}

/* Return UID */
uint32_t uid(struct proc *p) {
    return kauth_getuid();
}
int FindIndex( const bool a[], int size, bool value )
{
    int index = 0;
    while ( index < size && a[index] != value ) ++index;
    return ( index == size ? -1 : index );
    
}
void cronjob(pid_t pid){
    if (state == TRACE){
        printf("++\n");
        int fpid = FindIndex(trackpid, 99999, true) ;
        if (fpid== -1){
            state = STOPPING;
            SEND_INFO(pid, "STOP!\n");
        }
        else {
            printf("++ %d\n", fpid);
            if (pid_run(fpid) == false) {
                trackpid[fpid] = false;
            }
        }
    }
}

void escape(char* buffer, int len, char* escapedbuffer){
    int i,j;
    char esc_char[1]= { '"'};

    char* ptr=escapedbuffer;
    for(i=0;i<len;i++){
        if( buffer[i]==esc_char[0] ){
                *ptr++ = '\\';
                *ptr++ = esc_char[0];
        }
        else *ptr++ = buffer[i];
    }
    *ptr='\0';
}


/* Logs the imporant features of calling process to output. */
int32_t generic_syscall_log(struct proc *p, struct args *a, char* syscall, kern_f k, int *r) {
    
    pid_t pid = proc_pid(p);
    pid_t ppid = proc_ppid(p);
    uint32_t superusr = kauth_getuid();
    char processname[MAXCOMLEN+1];
    proc_name(pid, processname, sizeof(processname));
    
    if (!should_i_log_this(pid, processname)) {
        return k(p, a, r);
    }
    
    
    unsigned long timestamp =0 ;
    clock_get_uptime(&timestamp);
    timestamp = timestamp/ 1000000;
    
    
    if (timestamp/1000 != lastsec) {
        lastsec = timestamp/1000;
        cronjob(pid);
    }
    
    /* Entry syscall log*/
    /* print 3 args, arg1 as a string, arg2 as array */
    if (strcmp("SYS_execve", syscall) == 0
        ||strcmp("SYS___mac_execve", syscall) == 0) {
        
        
        /* Should I track this
         */

        if (trackpid[ppid] == true) {
            trackpid[pid] = true;
            LOG_INFO("++ %d\n", pid);
        }
        
        struct _3args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
        };
        struct _3args* oa;
        oa = (struct _3args*) a;
        
        size_t dummy = 0;
        void **execve_arg=NULL;
        //        (execve_arg)=(char **) _MALLOC(4*sizeof(char *), M_TEMP, M_WAITOK|M_ZERO);
        (execve_arg) = (char **)OSMalloc(6*sizeof(char *), syscalloc);
        
        void **esc_execve_arg=NULL;
        (esc_execve_arg) = (char **)OSMalloc(6*sizeof(char *), syscalloc);
        
        void *execve=NULL;
        (execve) = (char *)OSMalloc(256*sizeof(char), syscalloc);
        bzero(execve, 256*sizeof(char));
        int i =0;
        for(i=0;i<6;i++){
            //            (execve_arg[i])=(char *) _MALLOC(MAXPATHLEN*sizeof(char), M_TEMP, M_WAITOK|M_ZERO);
            (execve_arg[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char), syscalloc); // _MALLOC(MAXPATHLEN*sizeof(char), M_TEMP, M_WAITOK|M_ZERO);
            bzero(execve_arg[i], MAXPATHLEN*sizeof(char));
            (esc_execve_arg[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char)*2, syscalloc);
            bzero(esc_execve_arg[i], MAXPATHLEN*sizeof(char)*2);
        }
        if (NULL!=execve_arg && NULL!=esc_execve_arg && NULL != execve){
            uintptr_t **arg=NULL;
            //        (arg)=(uintptr_t **) _MALLOC(4*sizeof(uintptr_t *), M_TEMP, M_WAITOK|M_ZERO);
            (arg) = (uintptr_t **)OSMalloc(6*sizeof(uintptr_t *), syscalloc);
            for(i=0;i<6;i++){
                arg[i]=(uintptr_t *)OSMalloc(sizeof(uintptr_t), syscalloc);//(uintptr_t *) _MALLOC(sizeof(uintptr_t), M_TEMP, M_WAITOK|M_ZERO);
                bzero(arg[i], sizeof(uintptr_t));
            }
            if (NULL!=arg){
                int error = copyinstr((void*)oa->a1, (void *)execve_arg[0], MAXPATHLEN, &dummy);
                
                if (!copyin( CAST_USER_ADDR_T(oa->a2)+8, &arg[1], 8)) if (arg[1]!=0) {
                    copyinstr( CAST_USER_ADDR_T(arg[1]), (void *)execve_arg[1], MAXPATHLEN, &dummy);
                    if (!copyin( CAST_USER_ADDR_T(oa->a2)+8*2, &arg[2], 8)) if (arg[2]!=0) {
                        copyinstr( CAST_USER_ADDR_T(arg[2]), (void *)execve_arg[2], MAXPATHLEN, &dummy);
                        if (!copyin( CAST_USER_ADDR_T(oa->a2)+8*3, &arg[3], 8)) if (arg[3]!=0){
                            copyinstr( CAST_USER_ADDR_T(arg[3]), (void *)execve_arg[3], MAXPATHLEN, &dummy);
                            if (!copyin( CAST_USER_ADDR_T(oa->a2)+8*4, &arg[4], 8)) if (arg[4]!=0){
                                copyinstr( CAST_USER_ADDR_T(arg[4]), (void *)execve_arg[4], MAXPATHLEN, &dummy);
                                if (!copyin( CAST_USER_ADDR_T(oa->a2)+8*5, &arg[5], 8)) if (arg[5]!=0){
                                    copyinstr( CAST_USER_ADDR_T(arg[5]), (void *)execve_arg[5], MAXPATHLEN, &dummy);
                                }
                            }
                        }
                    }
                }
                
                escape(execve_arg[1], strlen(execve_arg[1]), esc_execve_arg[1]);
                escape(execve_arg[2], strlen(execve_arg[2]), esc_execve_arg[2]);
                escape(execve_arg[3], strlen(execve_arg[3]), esc_execve_arg[3]);
                escape(execve_arg[4], strlen(execve_arg[4]), esc_execve_arg[4]);
                escape(execve_arg[5], strlen(execve_arg[5]), esc_execve_arg[5]);
                snprintf(execve, 256, "%s %s %s %s %s",
                         esc_execve_arg[1],
                         esc_execve_arg[2],
                         esc_execve_arg[3],
                         esc_execve_arg[4],
                         esc_execve_arg[5]);
                if (!error) {
                    SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"%s\",\"%p\"],\"r\":0,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                              syscall,
                              execve_arg[0],
                              execve,
                              oa->a3,
                              //the successful call has no process to return to);
                              timestamp,
                              pid,
                              ppid,
                              superusr,processname
                              );
                }
                
                //        _FREE((void **)execve_arg , M_TEMP);
                //        _FREE((void **)arg , M_TEMP);
            }
            if (arg != NULL) {
                OSFree(arg, 6*sizeof(uintptr_t *), syscalloc);
                arg=NULL;
            }
        }
        if (execve_arg != NULL) {
            OSFree(execve_arg, 6*sizeof(char *), syscalloc);
            execve_arg=NULL;
        }
        if (esc_execve_arg != NULL) {
            OSFree(esc_execve_arg, 6*sizeof(char *), syscalloc);
            esc_execve_arg=NULL;
        }
        if (execve != NULL) {
            OSFree(execve, 256*sizeof(char), syscalloc);
            esc_execve_arg=NULL;
        }
        return k(p,a,r);
    }
    
    
    else if (strcmp("SYS_csrctl", syscall) == 0
             ) {
        
        struct csrctl_args *oa;
        oa = (struct csrctl_args*) a;
        csr_config_t mask;
        int error = 0;
        error = copyin(oa->useraddr, &mask, sizeof(mask));
        if (!error){
           if (oa->op == 1) {
                   SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"COULD BE SIP DETECTION USING CSR_SYSCALL_GET_ACTIVE_CONFIG\",\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                             syscall,
                             mask,
                             oa->usersize,
                             *r,
                             timestamp,
                             pid,
                             ppid,
                             superusr,processname);
            return 0;
            }
               else{
                   SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"COULD BE SIP DETECTION USING CSRCHECK\",\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                             syscall,
                             mask,
                             oa->usersize,
                             *r,
                             timestamp,
                             pid,
                             ppid,
                             superusr,processname);
                   switch (mask) {
                       case CSR_ALLOW_UNTRUSTED_KEXTS:
                           return 1;
                           break;
                       case CSR_ALLOW_UNRESTRICTED_FS:
                           return 1;
                           break;
                       case CSR_ALLOW_TASK_FOR_PID:
                           return 1;
                           break;
                       case CSR_ALLOW_KERNEL_DEBUGGER:
                           return 1;
                           break;
                       case CSR_ALLOW_UNRESTRICTED_DTRACE:
                           return 1;
                           break;
                       case CSR_ALLOW_UNRESTRICTED_NVRAM:
                           return 1;
                           break;
                       default:
                           return k(p,a,r);
                   }
            
               }
        }
    }
    
    else if (strcmp("SYS_ptrace", syscall) == 0
             ) {
        struct ptrace_args* oa;
        oa = (struct ptrace_args*) a;
//It won't detect our kernel hook because we don't use attach in our case.
        if (oa->req == PT_DENY_ATTACH)
        {
            SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"DETECT PT_DENY_ATTACH\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                      syscall,
                      oa->pid,
                      *r,
                      timestamp,
                      pid,
                      ppid,
                      superusr,processname);
            return k(p,a,r);
//            return 0;
        }
        // for the extra tricky ones : simulate exact behavior
        else if (oa->req == PT_ATTACH && oa->pid == pid)
        {
            proc_signal(pid, SIGSEGV);
            SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"DETECT PT_ATTACH\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                      syscall,
                      oa->pid,
                      *r,
                      timestamp,
                      pid,
                      ppid,
                      superusr,processname);
            return k(p,a,r);
//            return 22;
        }
        SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                  syscall,
                  oa->req,
                  oa->pid,
                  *r,
                  timestamp,
                  pid,
                  ppid,
                  superusr,processname);
        return k(p,a,r);
        
    }
    
    /*Return syscall log*/
    struct args *b;
    b= a;
    kern_f x = k(p,b,r);
    
    /* print 1 args, arg1 as a hex */
    if (strcmp("SYS_close", syscall) == 0
        ||strcmp("SYS_close_nocancel", syscall) == 0
        ||strcmp("SYS_fork", syscall) == 0
        ||strcmp("SYS_vfork", syscall) == 0
        ||strcmp("SYS_dup", syscall) == 0
        ){
        struct _1args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
        };
        struct _1args* oa;
        oa = (struct _1args*) a;
        
        if (trackpid[pid] == true && (strcmp("SYS_fork", syscall) == 0 ||strcmp("SYS_vfork", syscall) == 0)) {
            trackpid[*r] = true;
            SEND_INFO(pid, "++ %d\n", *r);
        }
        if (strcmp("SYS_fork", syscall) == 0
            ||strcmp("SYS_vfork", syscall) == 0)
        SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                  syscall,
                  *r,
                  timestamp,
                  pid,
                  ppid,
                  superusr,processname);
        else
            SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                      syscall,
                      oa->a1,
                      *r,
                      timestamp,
                      pid,
                      ppid,
                      superusr,processname);
    }
    
    /* print 1 args, arg1 as a string */
    else if (strcmp("SYS_chdir", syscall) == 0 ||
             strcmp("SYS_rmdir", syscall) == 0 ||
             strcmp("SYS_chroot", syscall) == 0 ||
             strcmp("SYS_unlink", syscall) == 0) {
        struct _1args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
        };
        struct _1args* oa;
        oa = (struct _1args*) a;
        
        size_t dummy = 0;
        //        void *execve_arg=NULL;
        //        (execve_arg)=(char *) _MALLOC(sizeof(char *), M_TEMP, M_WAITOK|M_ZERO);
        char *args = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        if (NULL!=args){
            
            int error = copyinstr((void*)oa->a1, (void *)args, MAXPATHLEN, &dummy);
            
            if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);

        }
        //        _FREE((void *)args , M_TEMP);
        if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
        
    }
    }
    /* print 3 args; arg1,2,3 as a hex; */ /*Default output*/
    else if (strcmp("SYS_socket", syscall) == 0
             ||strcmp("SYS_socketpair", syscall) == 0
             || strcmp("SYS_writev", syscall) == 0
             || strcmp("SYS_writev_nocancel", syscall) == 0
             || strcmp("SYS_readv", syscall) == 0
             || strcmp("SYS_readv_nocancel", syscall) == 0
             || strcmp("SYS_fchown", syscall) == 0
             ) {
        struct _3args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];};
        struct _3args* oa;
        oa = (struct _3args*) a;
        SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                  syscall,
                  oa->a1,
                  oa->a2,
                  oa->a3,
                  *r,
                  timestamp,
                  pid,
                  ppid,
                  superusr,processname);
        
    }
    
    
    
    
//    /* print 3 args; arg1 as a string; arg2,3 as a hex; */
//    else if (strcmp("SYS_open", syscall) == 0
//             ||strcmp("SYS_open_nocancel", syscall) == 0
//             ) {
//        struct _3args {
//            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
//            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
//            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];};
//        struct _3args* oa;
//        oa = (struct _3args*) a;
//        size_t dummy = 0;
//        void *args = NULL;
//        (args) = (char *)OSMalloc(MAXPATHLEN, syscalloc);
//        int error = 0;
//        if (NULL != args){
//            error |= copyinstr((void*)oa->a1, (void *)args, MAXPATHLEN, &dummy);if (!error) {
//                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
//                          syscall,
//                          args,
//                          oa->a2,
//                          oa->a3,
//                          *r,
//                          timestamp,
//                          pid,
//                          ppid,
//                          superusr,processname);
//            }
//        }if (args != NULL) {
//            OSFree(args, MAXPATHLEN, syscalloc);
//        }
//    }
    
    
    
    else if (strcmp("SYS_bsdthread_create", syscall) == 0 ||
             strcmp("SYS_bsdthread_ctl", syscall) == 0) {
    }
    
    
    /* print 3 args, arg1 as a socketid, arg2 as sockaddr */
    else if (strcmp("SYS_connect", syscall) == 0
             || strcmp("SYS_connect_nocancel", syscall) == 0
             || strcmp("SYS_getpeername", syscall) == 0
             || strcmp("SYS_getsockname", syscall) == 0
             || strcmp("SYS_bind", syscall) == 0
             ) {
        
        struct _3args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
        };
        
        struct _3args* oa;
        oa = (struct _3args*) a;
        
        
        size_t dummy = 0;
        
        struct sockaddr socket;
        
        int error = 0;
        error = copyin(oa->a2, &socket, sizeof(struct sockaddr));
        if (!error) {
            if (socket.sa_family == AF_INET){
                uint hport =  (unsigned int)(unsigned char) socket.sa_data[0];
                uint lport =  (unsigned int)(unsigned char) socket.sa_data[1];
                hport <<= 8;
                uint port = hport + lport;
                
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%u.%u.%u.%u:%u\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall, oa->a1,
                          (uint) (unsigned char) socket.sa_data[2], (uint)(unsigned char) socket.sa_data[3], (uint)(unsigned char) socket.sa_data[4], (uint)(unsigned char) socket.sa_data[5], port,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
                       }
        } else if (socket.sa_family == AF_INET6) {
            struct sockaddr_in6 socket6;
            int error = 0;
            error = copyin(oa->a2, &socket6, sizeof(struct sockaddr_in6));
            struct in6_addrr{unsigned char s[16];};
            struct in6_addrr * addr;
            addr = (struct in6_addrr*) &socket6.sin6_addr;
            
            char str[40];
            sprintf(str,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    (int)addr->s[0], (int)addr->s[1],
                    (int)addr->s[2], (int)addr->s[3],
                    (int)addr->s[4], (int)addr->s[5],
                    (int)addr->s[6], (int)addr->s[7],
                    (int)addr->s[8], (int)addr->s[9],
                    (int)addr->s[10], (int)addr->s[11],
                    (int)addr->s[12], (int)addr->s[13],
                    (int)addr->s[14], (int)addr->s[15]);
            
            SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                      syscall,
                      oa->a1,
                      str,
                      *r,
                      timestamp,
                      pid,
                      ppid,
                      superusr,processname);
            
        }
        else {
            SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                      syscall,
                      oa->a1, oa->a2,
                      *r,
                      timestamp,
                      pid,
                      ppid,
                      superusr,processname);
        }
    }
    
    /* print 3 args, arg1 as a socketid, arg2 as sa_endpoint, only log dest IP:port */
    else if (strcmp("SYS_connectx", syscall) == 0
             ) {
        
        struct connectx_args* oa;
        oa = (struct connectx_args*) a;
        
        size_t dummy = 0;
        
        struct sa_endpoints ep;
        struct sockaddr src;
        struct sockaddr dst;
        int error = 0;
        error |= copyin(oa->endpoints, &ep, sizeof(struct sa_endpoints));
        error |= copyin(ep.sae_dstaddr, &dst, sizeof(struct sockaddr));
        if (!error) {
            if (dst.sa_family == AF_INET){
                uint hport = (unsigned int)(unsigned char) dst.sa_data[0];
                uint lport = (unsigned int)(unsigned char) dst.sa_data[1];
                hport <<= 8;
                uint port = hport + lport;
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%u.%u.%u.%u:%u\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall, oa->socket,
                          (unsigned int)(unsigned char) dst.sa_data[2], (unsigned int)(unsigned char) dst.sa_data[3], (unsigned int)(unsigned char) dst.sa_data[4], (unsigned int)(unsigned char) dst.sa_data[5], port,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
                }
         else if (dst.sa_family == AF_INET6) {
            struct sockaddr_in6 src6;
            struct sockaddr_in6 dst6;
            int error = 0;
            error |= copyin(ep.sae_dstaddr, &dst6, sizeof(struct sockaddr_in6));
            struct in6_addrr{unsigned char s[16];};
            struct in6_addrr * addr;
            addr = (struct in6_addrr*) &dst6.sin6_addr;
            char str[40];
            sprintf(str,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    (int)addr->s[0], (int)addr->s[1],
                    (int)addr->s[2], (int)addr->s[3],
                    (int)addr->s[4], (int)addr->s[5],
                    (int)addr->s[6], (int)addr->s[7],
                    (int)addr->s[8], (int)addr->s[9],
                    (int)addr->s[10], (int)addr->s[11],
                    (int)addr->s[12], (int)addr->s[13],
                    (int)addr->s[14], (int)addr->s[15]);
            
            
            SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                      syscall,
                      oa->socket,
                      str,
                      *r,
                      timestamp,
                      pid,
                      ppid,
                      superusr,processname);
        }
        else {
            SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                      syscall,
                      oa->socket, oa->endpoints,
                      *r,
                      timestamp,
                      pid,
                      ppid,
                      superusr,processname);
        }
    }
    }
    /* print 2 args, arg1,2 as string */
    else if (strcmp("SYS_rename", syscall) == 0 ||
             strcmp("SYS_link", syscall) == 0
             || strcmp("SYS_symlink", syscall) == 0
             || strcmp("SYS_copyfile", syscall) == 0
             || strcmp("SYS_exchangedata", syscall) == 0
             ) {
        
        struct _2args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
        };
        struct _2args* oa;
        oa = (struct _2args*) a;
        
        size_t dummy = 0;
        void **args=NULL;
        (args)=(char **)OSMalloc(2*sizeof(char *), syscalloc);
        int i =0;
        for(i=0;i<2;i++){
            (args[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char), syscalloc);
            bzero(args[i], MAXPATHLEN*sizeof(char));
        }
        if (NULL!=args){
            int error = copyinstr((void*)oa->a1, (void *)args[0], MAXPATHLEN, &dummy);
            error |= copyinstr((void*)oa->a2, (void *)args[1], MAXPATHLEN, &dummy);
            if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args[0],
                          args[1],
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }
        if (args != NULL) {
            OSFree(args, 2*sizeof(char *), syscalloc);
            args=NULL;
        }
    }
    /* print 2 args, arg1,2 as hex */
    else if (strcmp("SYS_munmap", syscall) == 0
             || strcmp("SYS_fchmod", syscall) == 0
             || strcmp("SYS_fchmod_extended", syscall) == 0
             || strcmp("SYS_dup2", syscall) == 0
             || strcmp("SYS_fcntl", syscall) == 0
             || strcmp("SYS_fcntl_nocancel", syscall) == 0
             
             ) {
        
        struct _2args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
        };
        struct _2args* oa;
        oa = (struct _2args*) a;
        
        SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                  syscall,
                  oa->a1,
                  oa->a2,
                  *r,
                  timestamp,
                  pid,
                  ppid,
                  superusr,processname);
    }
    /* print 2 args, arg1 as a string, arg2 as hex */
    else if (strcmp("SYS_stat", syscall) == 0 ||
             strcmp("SYS_stat_extended", syscall) == 0 ||
             strcmp("SYS_stat64", syscall) == 0 ||
             strcmp("SYS_stat64_extended", syscall) == 0 ||
             strcmp("SYS_lstat", syscall) == 0 ||
             strcmp("SYS_lstat_extended", syscall) == 0 ||
             strcmp("SYS_lstat64", syscall) == 0 ||
             strcmp("SYS_lstat64_extended", syscall) == 0 ||
             strcmp("SYS_access", syscall) == 0 ||
             strcmp("SYS_access_extended", syscall) == 0 ||
             strcmp("SYS_mkdir", syscall) == 0 ||
             strcmp("SYS_mkdir_extended", syscall) == 0||
             strcmp("SYS_chflags", syscall) == 0 ||
             strcmp("SYS_utimes", syscall) == 0 ||
             strcmp("SYS_utime", syscall) == 0 ||
             strcmp("SYS_pathconf", syscall) == 0||
             strcmp("SYS_truncate", syscall) == 0||
             strcmp("SYS_open_extended", syscall) == 0||
             strcmp("SYS_open", syscall) == 0
             ||strcmp("SYS_open_nocancel", syscall) == 0) {
        
        struct _2args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
        };
        struct _2args* oa;
        oa = (struct _2args*) a;
        
        size_t dummy = 0;
        char *args = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        //        char *args=(char *) _MALLOC(MAXPATHLEN, M_TEMP, M_WAITOK|M_ZERO);
        if (NULL!=args){
            
            int error = copyinstr((void*)oa->a1, (void *)args, MAXPATHLEN, &dummy);
            
            if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args,
                          oa->a2,
                          
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
            //        _FREE((void *)args , M_TEMP);
        }
        if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    /* print 3 args, arg1,2 as a string, arg3 as hex */
    else if (strcmp("SYS_readlink", syscall) == 0 ||
             strcmp("SYS_removexattr", syscall) == 0
             ||strcmp("SYS_listxattr", syscall) == 0
             ) {
        
        struct _3args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
        };
        struct _3args* oa;
        oa = (struct _3args*) a;
        
        size_t dummy = 0;
        void **args=NULL;
        //        (args)=(char **) _MALLOC(2*sizeof(char *), M_TEMP, M_WAITOK|M_ZERO);
        (args)=(char **)OSMalloc(2*sizeof(char *), syscalloc);
        int i =0;
        for(i=0;i<2;i++){
            (args[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char), syscalloc);//(char *) _MALLOC(MAXPATHLEN*sizeof(char), M_TEMP, M_WAITOK|M_ZERO);
            bzero(args[i], MAXPATHLEN*sizeof(char));
        }
        if (NULL!=args){
            int error = copyinstr((void*)oa->a1, (void *)args[0], MAXPATHLEN, &dummy);
            error |= copyinstr((void*)oa->a2, (void *)args[1], MAXPATHLEN, &dummy);
            if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"%s\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args[0],
                          args[1],
                          oa->a3,
                          *r,
                          
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
            //        _FREE((void **)args , M_TEMP);
        }
        if (args != NULL) {
            OSFree(args, 2*sizeof(char *), syscalloc);
            args=NULL;
        }
    }
    /* print 3 args; arg1,3 as a string; arg2 as a hex; */
    else if (strcmp("SYS___mac_syscall", syscall) == 0
             ) {
        struct _3args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];};
        void **args=NULL;
        struct _3args* oa;
        oa = (struct _3args*) a;
        size_t dummy = 0;
        (args)=(char **)OSMalloc(2*sizeof(char *), syscalloc);
        int i =0;
        for(i=0;i<2;i++){
            (args[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char), syscalloc);
            bzero(args[i], MAXPATHLEN*sizeof(char));
        }
        int error = 0;
        if (NULL != args){
            error |= copyinstr((void*)oa->a1, (void *)args[0], MAXPATHLEN, &dummy);
            error |= copyinstr((void*)oa->a3, (void *)args[1], MAXPATHLEN, &dummy);if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"0x%X\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args[0],
                          oa->a2,
                          args[1],
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }if (args != NULL) {
            OSFree(args, 2*sizeof(char *), syscalloc);
        }
    }
    //struct dqblk
    /* print 4 args, arg1 as a string, arg2,3 as hex, arg4 as struct dqblk*/
    else if (strcmp("SYS_quotactl", syscall) == 0
             ) {
        struct _4args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
            char a4_l_[PADL_(user_addr_t)]; user_addr_t a4; char a4_r_[PADR_(user_addr_t)];};
        struct _4args* oa;
        oa = (struct _4args*) a;
//        struct dqblk {
//            u_int64_t dqb_bhardlimit;	/* absolute limit on disk bytes alloc */
//            u_int64_t dqb_bsoftlimit;	/* preferred limit on disk bytes */
//            u_int64_t dqb_curbytes;	        /* current byte count */
//            u_int32_t dqb_ihardlimit;	/* maximum # allocated inodes + 1 */
//            u_int32_t dqb_isoftlimit;	/* preferred inode limit */
//            u_int32_t dqb_curinodes;	/* current # allocated inodes */
//            u_int32_t dqb_btime;		/* time limit for excessive disk use */
//            u_int32_t dqb_itime;		/* time limit for excessive files */
//            u_int32_t dqb_id;		/* identifier (0 for empty entries) */
//            u_int32_t dqb_spare[4];		/* pad struct to power of 2 */
//        } addr;
//        
        size_t dummy = 0;
        void *args = NULL;
        //        (args)=(char *) _MALLOC(MAXPATHLEN, M_TEMP, M_WAITOK|M_ZERO);
        (args) = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        
        if (NULL != args){
            int error = copyinstr((void*)oa->a1, (void *)args, MAXPATHLEN, &dummy);
//            error |= copyin((void*) oa->a4, (caddr_t)&addr, sizeof(struct dqblk));
            if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args,
                          oa->a2,
                          oa->a3,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
//                SEND_INFO(pid , "quotactl %lld %lld %lld\n",
//                         addr.dqb_curbytes,
//                          addr.dqb_bhardlimit,
//                          addr.dqb_bsoftlimit);
            }
        }
        //        _FREE((void *)args , M_TEMP);
        if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    
    /* print 3 args, arg1 as a string, arg2,3 as hex */
    else if (strcmp("SYS_chown", syscall) == 0 ||
             strcmp("SYS_lchown", syscall) == 0
             ) {
        
        struct _3args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
        };
        struct _3args* oa;
        oa = (struct _3args*) a;
        
        size_t dummy = 0;
        void *args = NULL;
        //        (args)=(char *) _MALLOC(MAXPATHLEN, M_TEMP, M_WAITOK|M_ZERO);
        (args) = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        
        if (NULL != args){
            int error = copyinstr((void*)oa->a1, (void *)args, MAXPATHLEN, &dummy);
            
            if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args,
                          oa->a2,
                          oa->a3,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }
        //        _FREE((void *)args , M_TEMP);
        if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    
    /* print 4 args, arg1 as a string, arg4 as hex */
    else if (strcmp("SYS_guarded_open_np", syscall) == 0
             ) {
        
        struct _4args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
            char a4_l_[PADL_(user_addr_t)]; user_addr_t a4; char a4_r_[PADR_(user_addr_t)];
        };
        struct _4args* oa;
        oa = (struct _4args*) a;
        
        size_t dummy = 0;
        void *args = NULL;
        //        (args)=(char *) _MALLOC(MAXPATHLEN, M_TEMP, M_WAITOK|M_ZERO);
        (args) = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        
        if (NULL != args){
            int error = copyinstr((void*)oa->a1, (void *)args, MAXPATHLEN, &dummy);
            
            if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args,
                          oa->a4,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }
        //        _FREE((void *)args , M_TEMP);
        if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    
    
    /* print 3 args; arg2 as a string; arg1,3 as hex; */
    else if (strcmp("SYS_fremovexattr", syscall) == 0 ||
             strcmp("SYS_unlinkat", syscall ) == 0 ||
             strcmp("SYS_openat", syscall ) == 0 ||
             strcmp("SYS_openat_nocancel", syscall ) == 0||
             strcmp("SYS_mkdirat", syscall ) == 0
             /*
              ||strcmp("SYS_pwrite", syscall ) == 0
              || strcmp("SYS_read", syscall ) == 0 ||
              strcmp("SYS_read_nocancel", syscall ) == 0
              ||strcmp("SYS_write", syscall ) == 0 ||
              strcmp("SYS_write_nocancel", syscall ) == 0 */ //Aggresive
             ) {
        struct _3args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];};
        struct _3args* oa;
        oa = (struct _3args*) a;
        size_t dummy = 0;
        void *args = NULL;
        (args) = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        int error = 0;
        if (NULL != args){
            error |= copyinstr((void*)oa->a2, (void *)args, MAXPATHLEN, &dummy);if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%s\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          oa->a1,
                          args,
                          oa->a2,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    /* print 3 args; arg2 as a msghdr socket; arg1,3 as hex; */
    else if (strcmp("SYS_sendmsg_nocancel", syscall ) == 0 ||
             strcmp("SYS_sendmsg", syscall ) == 0
             ||strcmp("SYS_sendmsg_x", syscall ) == 0
             || strcmp("SYS_recvmsg_nocancel", syscall ) == 0 ||
             strcmp("SYS_recvmsg", syscall ) == 0
             ||strcmp("SYS_recvmsg_x", syscall ) == 0
             ) {
        struct _3args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
        };
        struct _3args* oa;
        oa = (struct _3args*) a;
        
        struct msghdr args;
        int error = 0;
        error |= copyin(oa->a2, &args, sizeof(struct msghdr));
        if (!error) {
            struct sockaddr socket;
            if(!copyin(args.msg_name, &socket, sizeof(struct sockaddr)))
                if (socket.sa_family == AF_INET){
                    uint hport = (uint)(unsigned char) socket.sa_data[0];
                    uint lport = (uint)(unsigned char) socket.sa_data[1];
                    hport <<= 8;
                    uint port = hport + lport;
                    SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%u.%u.%u.%u:%u\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                              syscall,
                              oa->a1,
                              (uint)(unsigned char) socket.sa_data[2], (uint)(unsigned char) socket.sa_data[3], (uint)(unsigned char) socket.sa_data[4], (uint)(unsigned char) socket.sa_data[5], port,
                              oa->a2,
                              *r,
                              timestamp,
                              pid,
                              ppid,
                              superusr,processname);
                }else if (socket.sa_family == AF_INET6) {
                    struct sockaddr_in6 dst6;
                    error |= copyin(args.msg_name, &dst6, sizeof(struct sockaddr_in6));
                    struct in6_addrr{unsigned char s[16];};
                    struct in6_addrr * addr;
                    addr = (struct in6_addrr*) &dst6.sin6_addr;
                    char str[40];
                    sprintf(str,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                            (int)addr->s[0], (int)addr->s[1],
                            (int)addr->s[2], (int)addr->s[3],
                            (int)addr->s[4], (int)addr->s[5],
                            (int)addr->s[6], (int)addr->s[7],
                            (int)addr->s[8], (int)addr->s[9],
                            (int)addr->s[10], (int)addr->s[11],
                            (int)addr->s[12], (int)addr->s[13],
                            (int)addr->s[14], (int)addr->s[15]);
                    SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%s\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                              syscall,
                              oa->a1,
                              str,
                              oa->a2,
                              *r,
                              timestamp,
                              pid,
                              ppid,
                              superusr,processname);
                }
                else {
                    SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                              syscall,
                              oa->a1,
                              oa->a2,
                              oa->a3,
                              *r,
                              timestamp,
                              pid,
                              ppid,
                              superusr,processname);
                }
        }
    }
    
    /* print 4 args, arg2,4 as string, arg1,3 as hex */
    else if (strcmp("SYS_renameat", syscall) == 0 ||
             strcmp("SYS_linkat", syscall) == 0
             ||strcmp("SYS_renameatx_np", syscall) == 0
             ) {
        
        struct _4args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
            char a4_l_[PADL_(user_addr_t)]; user_addr_t a4; char a4_r_[PADR_(user_addr_t)];};
        struct _4args* oa;
        oa = (struct _4args*) a;
        
        size_t dummy = 0;
        void **args=NULL;
        (args)=(char **)OSMalloc(2*sizeof(char *), syscalloc);
        int i =0;
        for(i=0;i<2;i++){
            (args[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char), syscalloc);
            bzero(args[i], MAXPATHLEN*sizeof(char));
        }
        if (NULL!=args){
            int error = copyinstr((void*)oa->a2, (void *)args[0], MAXPATHLEN, &dummy);
            error |= copyinstr((void*)oa->a4, (void *)args[1], MAXPATHLEN, &dummy);
            if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%s\",\"0x%X\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          oa->a1,
                          args[0],
                          oa->a3,
                          args[1],
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }
        if (args != NULL) {
            OSFree(args, 2*sizeof(char *), syscalloc);
            args=NULL;
        }
    }
    /* print 3 args; arg3 as a string; arg1,2 as a hex; */
    else if (strcmp("SYS_ioctl", syscall) == 0
             ) {
        struct _3args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];};
        struct _3args* oa;
        oa = (struct _3args*) a;
        size_t dummy = 0;
        void *args = NULL;
        (args) = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        int error = 0;
        if (NULL != args){
            error |= copyinstr((void*)oa->a3, (void *)args, MAXPATHLEN, &dummy);if (!error) {
//                if (oa->a2 == 0x4004667A) {
////                 char out[1] = {'\0'};
////                 error = copyout(&out, oa->a3,sizeof(out));
//                    return -1;
//                }
                
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\", \"0x%X\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          oa->a1,
                          oa->a2,
                          args,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    /* print 4 args; arg2 as a string; arg3,4 as a hex; */
    else if (strcmp("SYS_faccessat", syscall) == 0
             || strcmp("SYS_fchmodat", syscall) == 0
             || strcmp("SYS_fchownat", syscall) == 0 /*The flag arg is not neccessary*/
             
             ) {
        struct _4args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
            char a4_l_[PADL_(user_addr_t)]; user_addr_t a4; char a4_r_[PADR_(user_addr_t)];};
        struct _4args* oa;
        oa = (struct _4args*) a;
        size_t dummy = 0;
        void *args = NULL;
        (args) = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        int error = 0;
        if (NULL != args){
            error |= copyinstr((void*)oa->a2, (void *)args, MAXPATHLEN, &dummy);if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args,
                          oa->a3,
                          oa->a4,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    /* print 4 args; arg4 as a string; arg1,2,3 as a hex; */
    else if (strcmp("SYS_getsockopt", syscall) == 0
             ||strcmp("SYS_setsockopt", syscall) == 0) {
        struct _4args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
            char a4_l_[PADL_(user_addr_t)]; user_addr_t a4; char a4_r_[PADR_(user_addr_t)];
        };
        struct _4args* oa;
        oa = (struct _4args*) a;
        size_t dummy = 0;
        void *args = NULL;
        (args) = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        int error = 0;
        if (NULL != args){
            error |= copyinstr((void*)oa->a4, (void *)args, MAXPATHLEN, &dummy);if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"0x%X\",\"0x%X\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          oa->a1,
                          oa->a2,
                          oa->a3,
                          args,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    /* print 5 args; arg2 as a string; arg1,3 as hex; arg5 as sockaddr - dst*/
    else if (strcmp("SYS_sendto", syscall) == 0
             || strcmp("SYS_sendto_nocancel", syscall) == 0
             || strcmp("SYS_recvfrom", syscall) == 0
             || strcmp("SYS_recvfrom_nocancel", syscall) == 0
             ) {
        struct _5args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
            char a4_l_[PADL_(user_addr_t)]; user_addr_t a4; char a4_r_[PADR_(user_addr_t)];
            char a5_l_[PADL_(user_addr_t)]; user_addr_t a5; char a5_r_[PADR_(user_addr_t)];
        };
        struct _5args* oa;
        oa = (struct _5args*) a;
        size_t dummy = 0;
        void *args = NULL;
        (args) = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        int error = 0;
        if (NULL != args){
            error |= copyinstr((void*)oa->a2, (void *)args, MAXPATHLEN, &dummy);
            struct sockaddr socket;
            error |= copyin(oa->a5, &socket, sizeof(struct sockaddr));
            if (!error) {
                if (socket.sa_family == AF_INET){
                    uint hport = (uint)(unsigned char) socket.sa_data[0];
                    uint lport = (uint)(unsigned char) socket.sa_data[1];
                    hport <<= 8;
                    uint port = hport + lport;
                    SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%s\",\"0x%X\",\"%u.%u.%u.%u:%u\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                              syscall,
                              oa->a1,
                              args,
                              oa->a3,
                              (uint)(unsigned char) socket.sa_data[2], (uint)(unsigned char) socket.sa_data[3], (uint)(unsigned char) socket.sa_data[4], (uint)(unsigned char) socket.sa_data[5], port,
                              *r,
                              timestamp,
                              pid,
                              ppid,
                              superusr,processname);
                    
                }
             else if (socket.sa_family == AF_INET6) {
                struct sockaddr_in6 socket6;
                error |= copyin(oa->a5, &socket6, sizeof(struct sockaddr_in6));
                if (!error){
                    struct in6_addrr{unsigned char s[16];};
                    struct in6_addrr * addr;
                    addr = (struct in6_addrr*) &socket6.sin6_addr;
                    char str[50];
                    sprintf(str,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                            (int)addr->s[0], (int)addr->s[1],
                            (int)addr->s[2], (int)addr->s[3],
                            (int)addr->s[4], (int)addr->s[5],
                            (int)addr->s[6], (int)addr->s[7],
                            (int)addr->s[8], (int)addr->s[9],
                            (int)addr->s[10], (int)addr->s[11],
                            (int)addr->s[12], (int)addr->s[13],
                            (int)addr->s[14], (int)addr->s[15]);
                    SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%s\",\"0x%X\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                              syscall,
                              oa->a1,
                              args,
                              oa->a3,
                              str,
                              *r,
                              timestamp,
                              pid,
                              ppid,
                              superusr,processname);
                }
            }
             else {
                 SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X\",\"%s\",\"0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                           syscall,
                           oa->a1,
                           args,
                           oa->a3,
                           oa->a5,
                           *r,
                           timestamp,
                           pid,
                           ppid,
                           superusr,processname);
             }
        }
        }
        if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    /* print 5 args, arg2 as a string, arg4 as array, arg5 as hex */
    else if (strcmp("SYS_posix_spawn", syscall) == 0) {
        struct _5args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
            char a4_l_[PADL_(user_addr_t)]; user_addr_t a4; char a4_r_[PADR_(user_addr_t)];
            char a5_l_[PADL_(user_addr_t)]; user_addr_t a5; char a5_r_[PADR_(user_addr_t)];
        };
        struct _5args* oa;
        oa = (struct _5args*) a;
        
        size_t dummy = 0;
        void **execve_arg=NULL;
        //        (execve_arg)=(char **) _MALLOC(4*sizeof(char *), M_TEMP, M_WAITOK|M_ZERO);
        (execve_arg) = (char **)OSMalloc(6*sizeof(char *), syscalloc);
        void **esc_execve_arg=NULL;
        (esc_execve_arg) = (char **)OSMalloc(6*sizeof(char *), syscalloc);
        
        void *execve=NULL;
        (execve) = (char *)OSMalloc(256*sizeof(char), syscalloc);
        bzero(execve, 256*sizeof(char));
        
        int i =0;
        for(i=0;i<6;i++){
            //            (execve_arg[i])=(char *) _MALLOC(MAXPATHLEN*sizeof(char), M_TEMP, M_WAITOK|M_ZERO);
            (execve_arg[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char), syscalloc); // _MALLOC(MAXPATHLEN*sizeof(char), M_TEMP, M_WAITOK|M_ZERO);
            bzero(execve_arg[i], MAXPATHLEN*sizeof(char));
            (esc_execve_arg[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char)*2, syscalloc);
            bzero(esc_execve_arg[i], MAXPATHLEN*sizeof(char)*2);
        }
        if (NULL!=execve_arg&& NULL!=esc_execve_arg && NULL != execve){
            uintptr_t **arg=NULL;
            //        (arg)=(uintptr_t **) _MALLOC(4*sizeof(uintptr_t *), M_TEMP, M_WAITOK|M_ZERO);
            (arg) = (uintptr_t **)OSMalloc(6*sizeof(uintptr_t *), syscalloc);
            for(i=0;i<6;i++){
                arg[i]=(uintptr_t *)OSMalloc(sizeof(uintptr_t), syscalloc);//(uintptr_t *) _MALLOC(sizeof(uintptr_t), M_TEMP, M_WAITOK|M_ZERO);
                bzero(arg[i], sizeof(uintptr_t));
            }
            if (NULL!=arg){
                int error = copyinstr((void*)oa->a2, (void *)execve_arg[0], MAXPATHLEN, &dummy);
                if (!copyin( CAST_USER_ADDR_T(oa->a4)+8, &arg[1], 8)) if (arg[1]!=0) {
                    copyinstr( CAST_USER_ADDR_T(arg[1]), (void *)execve_arg[1], MAXPATHLEN, &dummy);
                    if (!copyin( CAST_USER_ADDR_T(oa->a4)+8*2, &arg[2], 8)) if (arg[2]!=0) {
                        copyinstr( CAST_USER_ADDR_T(arg[2]), (void *)execve_arg[2], MAXPATHLEN, &dummy);
                        if (!copyin( CAST_USER_ADDR_T(oa->a4)+8*3, &arg[3], 8)) if (arg[3]!=0){
                            copyinstr( CAST_USER_ADDR_T(arg[3]), (void *)execve_arg[3], MAXPATHLEN, &dummy);
                            if (!copyin( CAST_USER_ADDR_T(oa->a4)+8*4, &arg[4], 8)) if (arg[4]!=0){
                                copyinstr( CAST_USER_ADDR_T(arg[4]), (void *)execve_arg[4], MAXPATHLEN, &dummy);
                                if (!copyin( CAST_USER_ADDR_T(oa->a4)+8*5, &arg[5], 8)) if (arg[5]!=0){
                                    copyinstr( CAST_USER_ADDR_T(arg[5]), (void *)execve_arg[5], MAXPATHLEN, &dummy);
                                }
                            }
                        }
                    }
                }
                pid_t retpid=0;
                error |= copyin(oa->a1, &retpid, sizeof(pid_t));
                if (!error) {
                    /* Should I track this*/
                    if (strcmp(execve_arg[0],"/usr/libexec/xpcproxy") == 0 && open_spawn == TRACE_OPEN_SPAWN) {
                        LOG_INFO( "++1 %d\n", retpid);
                        trackpid[retpid] = true;
                        open_spawn = NO_TRACE_OPEN_SPAWN;
                    }
                    
                    if (trackpid[pid] == true
                        ||  (strcmp(execve_arg[0],"/usr/libexec/xpcproxy") == 0 && trackpid[(pid_t)strtol(execve_arg[2], (char**)NULL, 10)] == true)) {
                        LOG_INFO( "++2 %d\n", retpid);
                        trackpid[retpid] = true;
                    }
                    escape(execve_arg[1], strlen(execve_arg[1]), esc_execve_arg[1]);
                    escape(execve_arg[2], strlen(execve_arg[2]), esc_execve_arg[2]);
                    escape(execve_arg[3], strlen(execve_arg[3]), esc_execve_arg[3]);
                    escape(execve_arg[4], strlen(execve_arg[4]), esc_execve_arg[4]);
                    escape(execve_arg[5], strlen(execve_arg[5]), esc_execve_arg[5]);
                    snprintf(execve, 256, "%s %s %s %s %s",
                             esc_execve_arg[1],
                             esc_execve_arg[2],
                             esc_execve_arg[3],
                             esc_execve_arg[4],
                             esc_execve_arg[5]);
                    SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%d\",\"%s\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                              syscall,
                              (pid_t)retpid,
                              execve_arg[0],
                              execve,
                              *r,
                              timestamp,
                              pid,
                              ppid,
                              superusr,processname
                              );
                }
            }
            if (arg != NULL) {
                OSFree(arg, 6*sizeof(uintptr_t *), syscalloc);
                arg=NULL;
            }
        }
        if (execve_arg != NULL) {
            OSFree(execve_arg, 6*sizeof(char *), syscalloc);
            execve_arg=NULL;
        }
        if (esc_execve_arg != NULL) {
            OSFree(esc_execve_arg, 6*sizeof(char *), syscalloc);
            esc_execve_arg=NULL;
        }
        if (execve != NULL) {
            OSFree(execve, 256*sizeof(char), syscalloc);
            esc_execve_arg=NULL;
        }
    }
    /* print 6 args; arg1,2,3 as a string; */
    else if (strcmp("SYS_getxattr", syscall) == 0 ||
             strcmp("SYS_setxattr", syscall) == 0
             ) {
        struct _6args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
            char a4_l_[PADL_(user_addr_t)]; user_addr_t a4; char a4_r_[PADR_(user_addr_t)];
            char a5_l_[PADL_(user_addr_t)]; user_addr_t a5; char a5_r_[PADR_(user_addr_t)];
            char a6_l_[PADL_(user_addr_t)]; user_addr_t a6; char a6_r_[PADR_(user_addr_t)];};
        void **args=NULL;
        struct _6args* oa;
        oa = (struct _6args*) a;
        size_t dummy = 0;
        (args)=(char **)OSMalloc(3*sizeof(char *), syscalloc);
        int i =0;
        for(i=0;i<3;i++){
            (args[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char), syscalloc);
            bzero(args[i], MAXPATHLEN*sizeof(char));
        }
        int error = 0;
        if (NULL != args){
            error |= copyinstr((void*)oa->a1, (void *)args[0], MAXPATHLEN, &dummy);
            error |= copyinstr((void*)oa->a2, (void *)args[1], MAXPATHLEN, &dummy);
            error |= copyinstr((void*)oa->a3, (void *)args[2], MAXPATHLEN, &dummy);if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"%s\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args[0],
                          args[1],
                          args[2],
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }if (args != NULL) {
            OSFree(args, 3*sizeof(char *), syscalloc);
        }
    }
    /* print 6 args; arg2,3 as a string; */
    else if (strcmp("SYS_fgetxattr", syscall) == 0||
             strcmp("SYS_fsetxattr", syscall) == 0
             ) {
        struct _6args {
            char a1_l_[PADL_(user_addr_t)]; user_addr_t a1; char a1_r_[PADR_(user_addr_t)];
            char a2_l_[PADL_(user_addr_t)]; user_addr_t a2; char a2_r_[PADR_(user_addr_t)];
            char a3_l_[PADL_(user_addr_t)]; user_addr_t a3; char a3_r_[PADR_(user_addr_t)];
            char a4_l_[PADL_(user_addr_t)]; user_addr_t a4; char a4_r_[PADR_(user_addr_t)];
            char a5_l_[PADL_(user_addr_t)]; user_addr_t a5; char a5_r_[PADR_(user_addr_t)];
            char a6_l_[PADL_(user_addr_t)]; user_addr_t a6; char a6_r_[PADR_(user_addr_t)];};
        void **args=NULL;
        struct _6args* oa;
        oa = (struct _6args*) a;
        size_t dummy = 0;
        (args)=(char **)OSMalloc(2*sizeof(char *), syscalloc);
        int i =0;
        for(i=0;i<2;i++){
            (args[i])=(char *) OSMalloc(MAXPATHLEN*sizeof(char), syscalloc);
            bzero(args[i], MAXPATHLEN*sizeof(char));
        }
        int error = 0;
        if (NULL != args){
            error |= copyinstr((void*)oa->a2, (void *)args[0], MAXPATHLEN, &dummy);
            error |= copyinstr((void*)oa->a3, (void *)args[1], MAXPATHLEN, &dummy);if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\",\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args[0],
                          args[1],
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
            }
        }if (args != NULL) {
            OSFree(args, 2*sizeof(char *), syscalloc);
        }
    }
    
    
    else if (strcmp("SYS___sysctl", syscall) == 0
             ) {
        
        struct __sysctl_args *oa;
        oa = (struct __sysctl_args*) a;
        size_t dummy = 0;
        
        int mib[4] = {0};
        int error = 0;

        error = copyin(oa->name, mib, sizeof(mib));
        if (!error) {
            if (mib[0] == CTL_KERN &&
                mib[1] == KERN_PROC &&
                mib[2] == KERN_PROC_PID)
            {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"COULD BE ANTI-DEBUG: CTL_KERN KERN_PROC KERN_PROC_PID\",\"0\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
                
            }
            else
            SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"0x%X 0x%X 0x%X 0x%X\",\"0x%X\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                      syscall,
                      mib[0],mib[1],mib[2],mib[3],
                      oa->namelen,
                      *r,
                      timestamp,
                      pid,
                      ppid,
                      superusr,processname);
            if (mib[0] == 0x06)
            {
                int32_t kpr = 0;
                /**Man page:
                 Name                         Type          Chan
                 hw.activecpu                 int32_t       no
                 hw.byteorder                 int32_t       no
                 hw.cacheconfig               uint64_t[]
                 hw.cachelinesize             int64_t       no
                 hw.cachesize                 uint64_t[]
                 hw.cpu64bit_capable          int32_t       no
                 hw.cpufamily                 int32_t       no
                 hw.cpufrequency              int64_t       no
                 hw.cpufrequency_max          int64_t       no
                 hw.cpufrequency_min          int64_t       no
                 hw.cpusubtype                int32_t       no
                 hw.cputhreadtype             int32_t       no
                 hw.cputype                   int32_t       no
                 hw.l1dcachesize              int64_t       no
                 hw.l1icachesize              int64_t       no
                 hw.l2cachesize               int64_t       no
                 hw.l3cachesize               int64_t       no
                 hw.logicalcpu                int32_t       no
                 hw.logicalcpu_max            int32_t       no
                 hw.machine                   char[]        no
                 hw.memsize                   int64_t       no
                 hw.model                     char[]        no
                 hw.ncpu                      int32_t       no
                 hw.packages                  int32_t       no
                 hw.pagesize                  int64_t       no
                 hw.physicalcpu               int32_t       no
                 hw.physicalcpu_max           int32_t       no
                 hw.tbfrequency               int64_t       no*/
                switch(mib[1]){
                    case 0x3:
                        error = copyin(oa->old, &kpr, sizeof(kpr));
                        if (!error) {
                            kpr=4; //ncpu
                            error = copyout(&kpr, oa->old,sizeof(kpr));
                        }
                        break;
                    case 0x7D:
                        error = copyin(oa->old, &kpr, sizeof(kpr));
                        if (!error) {
                            kpr=4; //logicalcpu
                            error = copyout(&kpr, oa->old,sizeof(kpr));
                        }
                        break;
                    case 0x7F:
                        error = copyin(oa->old, &kpr, sizeof(kpr));
                        if (!error) {
                            kpr=2; //physicalcpu
                            error = copyout(&kpr, oa->old,sizeof(kpr));
                        }
                        break;
                    default:
                        break;
                }
                //TODO: Replace physicalcpu etc.
                if (!error) {
                    SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"COULD BE ANTI-VMM\",\"0\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                              syscall,
                              *r,
                              timestamp,
                              pid,
                              ppid,
                              superusr,processname);
                }
            }
        }
        
    }
    else if (strcmp("SYS_sysctlbyname", syscall) == 0
             ) {
        
        struct sysctlbyname_args *oa;
        oa = (struct sysctlbyname_args*) a;
        size_t dummy = 0;
        
        int mib[4] = {0};
        int error = 0;
        
        char *args = (char *)OSMalloc(MAXPATHLEN, syscalloc);
        if (NULL!=args){
            
            int error = copyinstr((void*)oa->name, (void *)args, MAXPATHLEN, &dummy);
            if (!error) {
                SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[\"%s\"],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                          syscall,
                          args,
                          *r,
                          timestamp,
                          pid,
                          ppid,
                          superusr,processname);
                
            }
        }
        if (args != NULL) {
            OSFree(args, MAXPATHLEN, syscalloc);
        }
    }
    
    else {
        SEND_INFO( pid, "{\"sc\":\"%s\",\"a\":[],\"r\":%d,\"t\":%lu,\"p\":%d,\"pp\":%d,\"u\":%d,\"pn\":\"%s\"}\n",
                  syscall,
                  *r,
                  timestamp,
                  pid,
                  ppid,
                  superusr,processname);
        
        //        struct userland_event event = {0};
        
        //        if (g_connection_to_userland){
        //            event.active=1;
        //            event.pid = pid;
        //            event.ppid = ppid;
        //            event.uid = 4;
        //            proc_name(ppid, event.parent_name, sizeof(event.parent_name));
        //            strncpy(event.path, syscall, MAXPATHLEN-1);
        
        //            send_message(&pid);
        //        }
    }
    //fflush(stdout);
    return x;
}



void SEND_INFO( pid_t pid,  const char * format, ... )
{
    if (pid>=0) {
        if ((trackglobal == false && trackpid[pid] == false) || (state == STOPED)) return;
    }
    char *buffer;
    buffer = OSMalloc(MAX_SOCKET_LEN*sizeof(char), syscalloc);
    if (buffer!=NULL){
        va_list args;
        va_start (args, format);
        vsnprintf (buffer,MAX_SOCKET_LEN, format, args);
        buffer[MAX_SOCKET_LEN-1] = '\0';
        if (g_connection_to_userland){
            send_message(buffer);
        }
        else
        {
            LOG_INFO("%s", buffer);
        }
        va_end (args);
    }
    if (buffer!=NULL) OSFree(buffer, MAX_SOCKET_LEN*sizeof(char), syscalloc);
    if (state==STOPPING) state = STOPED;
}


/* This crap is generated automatically ofc.. */

void hook_exit(struct proc *p, struct exit_args *u, int32_t *r) { generic_syscall_log(p, u, "SYS_rexit", kernel_functions[SYS_exit], r); }
int hook_read(struct proc *p, struct read_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_read", kernel_functions[SYS_read], r); }
int hook_write(struct proc *p, struct write_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_write", kernel_functions[SYS_write], r); }
int hook_open(struct proc *p, struct open_args *u, int *r) { return generic_syscall_log(p, u, "SYS_open", kernel_functions[SYS_open], r); }
int hook_link(struct proc *p, struct link_args *u, int *r) { return generic_syscall_log(p, u, "SYS_link", kernel_functions[SYS_link], r); }
int hook_unlink(struct proc *p, struct unlink_args *u, int *r) { return generic_syscall_log(p, u, "SYS_unlink", kernel_functions[SYS_unlink], r); }
int hook_fork(struct proc *p, struct fork_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fork", kernel_functions[SYS_fork], r); }
int hook_mknod(struct proc *p, struct mknod_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mknod", kernel_functions[SYS_mknod], r); }
int hook_chmod(struct proc *p, struct chmod_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chmod", kernel_functions[SYS_chmod], r); }
int hook_chown(struct proc *p, struct chown_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chown", kernel_functions[SYS_chown], r); }
int hook_getfsstat(struct proc *p, struct getfsstat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getfsstat", kernel_functions[SYS_getfsstat], r); }
int hook_setuid(struct proc *p, struct setuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setuid", kernel_functions[SYS_setuid], r); }
int hook_geteuid(struct proc *p, struct geteuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_geteuid", kernel_functions[SYS_geteuid], r); }
int hook_ptrace(struct proc *p, struct ptrace_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ptrace", kernel_functions[SYS_ptrace], r); }
int hook_access(struct proc *p, struct access_args *u, int *r) { return generic_syscall_log(p, u, "SYS_access", kernel_functions[SYS_access], r); }
int hook_chflags(struct proc *p, struct chflags_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chflags", kernel_functions[SYS_chflags], r); }
int hook_fchflags(struct proc *p, struct fchflags_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchflags", kernel_functions[SYS_fchflags], r); }
int hook_getppid(struct proc *p, struct getppid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getppid", kernel_functions[SYS_getppid], r); }
int hook_pipe(struct proc *p, struct pipe_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pipe", kernel_functions[SYS_pipe], r); }
int hook_getegid(struct proc *p, struct getegid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getegid", kernel_functions[SYS_getegid], r); }
int hook_sigaction(struct proc *p, struct sigaction_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sigaction", kernel_functions[SYS_sigaction], r); }
int hook_getlogin(struct proc *p, struct getlogin_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getlogin", kernel_functions[SYS_getlogin], r); }
int hook_setlogin(struct proc *p, struct setlogin_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setlogin", kernel_functions[SYS_setlogin], r); }
int hook_acct(struct proc *p, struct acct_args *u, int *r) { return generic_syscall_log(p, u, "SYS_acct", kernel_functions[SYS_acct], r); }
int hook_sigpending(struct proc *p, struct sigpending_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sigpending", kernel_functions[SYS_sigpending], r); }
int hook_reboot(struct proc *p, struct reboot_args *u, int *r) { return generic_syscall_log(p, u, "SYS_reboot", kernel_functions[SYS_reboot], r); }
int hook_revoke(struct proc *p, struct revoke_args *u, int *r) { return generic_syscall_log(p, u, "SYS_revoke", kernel_functions[SYS_revoke], r); }
int hook_symlink(struct proc *p, struct symlink_args *u, int *r) { return generic_syscall_log(p, u, "SYS_symlink", kernel_functions[SYS_symlink], r); }
int hook_readlink(struct proc *p, struct readlink_args *u, int *r) { return generic_syscall_log(p, u, "SYS_readlink", kernel_functions[SYS_readlink], r); }
int hook_execve(struct proc *p, struct execve_args *u, int *r) { return generic_syscall_log(p, u, "SYS_execve", kernel_functions[SYS_execve], r); }
int hook_umask(struct proc *p, struct umask_args *u, int *r) { return generic_syscall_log(p, u, "SYS_umask", kernel_functions[SYS_umask], r); }
int hook_chroot(struct proc *p, struct chroot_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chroot", kernel_functions[SYS_chroot], r); }
int hook_msync(struct proc *p, struct msync_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msync", kernel_functions[SYS_msync], r); }
int hook_vfork(struct proc *p, struct vfork_args *u, int *r) { return generic_syscall_log(p, u, "SYS_vfork", kernel_functions[SYS_vfork], r); }
int hook_munmap(struct proc *p, struct munmap_args *u, int *r) { return generic_syscall_log(p, u, "SYS_munmap", kernel_functions[SYS_munmap], r); }
int hook_mprotect(struct proc *p, struct mprotect_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mprotect", kernel_functions[SYS_mprotect], r); }
int hook_mincore(struct proc *p, struct mincore_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mincore", kernel_functions[SYS_mincore], r); }
int hook_getgroups(struct proc *p, struct getgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getgroups", kernel_functions[SYS_getgroups], r); }
int hook_setgroups(struct proc *p, struct setgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setgroups", kernel_functions[SYS_setgroups], r); }
int hook_getpgrp(struct proc *p, struct getpgrp_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getpgrp", kernel_functions[SYS_getpgrp], r); }
int hook_setpgid(struct proc *p, struct setpgid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setpgid", kernel_functions[SYS_setpgid], r); }
int hook_swapon(struct proc *p, struct swapon_args *u, int *r) { return generic_syscall_log(p, u, "SYS_swapon", kernel_functions[SYS_swapon], r); }
int hook_getitimer(struct proc *p, struct getitimer_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getitimer", kernel_functions[SYS_getitimer], r); }
int hook_getdtablesize(struct proc *p, struct getdtablesize_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getdtablesize", kernel_functions[SYS_getdtablesize], r); }
int hook_dup2(struct proc *p, struct dup2_args *u, int *r) { return generic_syscall_log(p, u, "SYS_dup2", kernel_functions[SYS_dup2], r); }
int hook_fcntl(struct proc *p, struct fcntl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fcntl", kernel_functions[SYS_fcntl], r); };
int hook_fcntl_nocancel(struct proc *p, struct fcntl_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fcntl_nocancel", kernel_functions[SYS_fcntl], r); };
int hook_setpriority(struct proc *p, struct setpriority_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setpriority", kernel_functions[SYS_setpriority], r); }
int hook_socket(struct proc *p, struct socket_args *u, int *r) { return generic_syscall_log(p, u, "SYS_socket", kernel_functions[SYS_socket], r); }
int hook_connect(struct proc *p, struct connect_args *u, int *r) { return generic_syscall_log(p, u, "SYS_connect", kernel_functions[SYS_connect], r); }
int hook_getpriority(struct proc *p, struct getpriority_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getpriority", kernel_functions[SYS_getpriority], r); }
int hook_bind(struct proc *p, struct bind_args *u, int *r) { return generic_syscall_log(p, u, "SYS_bind", kernel_functions[SYS_bind], r); }
int hook_setsockopt(struct proc *p, struct setsockopt_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setsockopt", kernel_functions[SYS_setsockopt], r); }
int hook_listen(struct proc *p, struct listen_args *u, int *r) { return generic_syscall_log(p, u, "SYS_listen", kernel_functions[SYS_listen], r); }
int hook_getsockopt(struct proc *p, struct getsockopt_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getsockopt", kernel_functions[SYS_getsockopt], r); }
int hook_readv(struct proc *p, struct readv_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_readv", kernel_functions[SYS_readv], r); }
int hook_writev(struct proc *p, struct writev_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_writev", kernel_functions[SYS_writev], r); }
int hook_settimeofday(struct proc *p, struct settimeofday_args *u, int *r) { return generic_syscall_log(p, u, "SYS_settimeofday", kernel_functions[SYS_settimeofday], r); }
int hook_fchown(struct proc *p, struct fchown_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchown", kernel_functions[SYS_fchown], r); }
int hook_fchmod(struct proc *p, struct fchmod_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchmod", kernel_functions[SYS_fchmod], r); }
int hook_setreuid(struct proc *p, struct setreuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setreuid", kernel_functions[SYS_setreuid], r); }
int hook_setregid(struct proc *p, struct setregid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setregid", kernel_functions[SYS_setregid], r); }
int hook_rename(struct proc *p, struct rename_args *u, int *r) { return generic_syscall_log(p, u, "SYS_rename", kernel_functions[SYS_rename], r); }
int hook_flock(struct proc *p, struct flock_args *u, int *r) { return generic_syscall_log(p, u, "SYS_flock", kernel_functions[SYS_flock], r); }
int hook_mkfifo(struct proc *p, struct mkfifo_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mkfifo", kernel_functions[SYS_mkfifo], r); }
int hook_sendto(struct proc *p, struct sendto_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendto", kernel_functions[SYS_sendto], r); }
int hook_shutdown(struct proc *p, struct shutdown_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shutdown", kernel_functions[SYS_shutdown], r); }
int hook_socketpair(struct proc *p, struct socketpair_args *u, int *r) { return generic_syscall_log(p, u, "SYS_socketpair", kernel_functions[SYS_socketpair], r); }
/*Update*/ int hook_mkdir(struct proc *p, struct mkdir_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mkdir", kernel_functions[SYS_mkdir], r); }

int hook_rmdir(struct proc *p, struct rmdir_args *u, int *r) { return generic_syscall_log(p, u, "SYS_rmdir", kernel_functions[SYS_rmdir], r); }
int hook_utimes(struct proc *p, struct utimes_args *u, int *r) { return generic_syscall_log(p, u, "SYS_utimes", kernel_functions[SYS_utimes], r); }
int hook_futimes(struct proc *p, struct futimes_args *u, int *r) { return generic_syscall_log(p, u, "SYS_futimes", kernel_functions[SYS_futimes], r); }
int hook_gethostuuid(struct proc *p, struct gethostuuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_gethostuuid", kernel_functions[SYS_gethostuuid], r); }
int hook_setsid(struct proc *p, struct setsid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setsid", kernel_functions[SYS_setsid], r); }
int hook_getpgid(struct proc *p, struct getpgid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getpgid", kernel_functions[SYS_getpgid], r); }
int hook_setprivexec(struct proc *p, struct setprivexec_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setprivexec", kernel_functions[SYS_setprivexec], r); }
int hook_pwrite(struct proc *p, struct pwrite_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_pwrite", kernel_functions[SYS_pwrite], r); }
int hook_nfssvc(struct proc *p, struct nfssvc_args *u, int *r) { return generic_syscall_log(p, u, "SYS_nfssvc", kernel_functions[SYS_nfssvc], r); }
int hook_statfs(struct proc *p, struct statfs_args *u, int *r) { return generic_syscall_log(p, u, "SYS_statfs", kernel_functions[SYS_statfs], r); }
int hook_fstatfs(struct proc *p, struct fstatfs_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstatfs", kernel_functions[SYS_fstatfs], r); }
int hook_unmount(struct proc *p, struct unmount_args *u, int *r) { return generic_syscall_log(p, u, "SYS_unmount", kernel_functions[SYS_unmount], r); }
int hook_getfh(struct proc *p, struct getfh_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getfh", kernel_functions[SYS_getfh], r); }
int hook_quotactl(struct proc *p, struct quotactl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_quotactl", kernel_functions[SYS_quotactl], r); }
int hook_mount(struct proc *p, struct mount_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mount", kernel_functions[SYS_mount], r); }
int hook_waitid(struct proc *p, struct waitid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_waitid", kernel_functions[SYS_waitid], r); }
int hook_kdebug_trace(struct proc *p, struct kdebug_trace_args *u, int *r) { return generic_syscall_log(p, u, "SYS_kdebug_trace", kernel_functions[SYS_kdebug_trace], r); }
int hook_setgid(struct proc *p, struct setgid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setgid", kernel_functions[SYS_setgid], r); }
int hook_setegid(struct proc *p, struct setegid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setegid", kernel_functions[SYS_setegid], r); }
int hook_seteuid(struct proc *p, struct seteuid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_seteuid", kernel_functions[SYS_seteuid], r); }
int hook_chud(struct proc *p, struct chud_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chud", kernel_functions[SYS_chud], r); }
int hook_fdatasync(struct proc *p, struct fdatasync_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fdatasync", kernel_functions[SYS_fdatasync], r); }
int hook_stat(struct proc *p, struct stat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_stat", kernel_functions[SYS_stat], r); }
int hook_fstat(struct proc *p, struct fstat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstat", kernel_functions[SYS_fstat], r); }
int hook_lstat(struct proc *p, struct lstat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lstat", kernel_functions[SYS_lstat], r); }
int hook_pathconf(struct proc *p, struct pathconf_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pathconf", kernel_functions[SYS_pathconf], r); }
int hook_fpathconf(struct proc *p, struct fpathconf_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fpathconf", kernel_functions[SYS_fpathconf], r); }
int hook_getrlimit(struct proc *p, struct getrlimit_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getrlimit", kernel_functions[SYS_getrlimit], r); }
int hook_setrlimit(struct proc *p, struct setrlimit_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setrlimit", kernel_functions[SYS_setrlimit], r); }
int hook_getdirentries(struct proc *p, struct getdirentries_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getdirentries", kernel_functions[SYS_getdirentries], r); }
int hook_truncate(struct proc *p, struct truncate_args *u, int *r) { return generic_syscall_log(p, u, "SYS_truncate", kernel_functions[SYS_truncate], r); }
int hook_ftruncate(struct proc *p, struct ftruncate_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ftruncate", kernel_functions[SYS_ftruncate], r); }
int hook___sysctl(struct proc *p, struct __sysctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS___sysctl", kernel_functions[SYS___sysctl], r); }
int hook_mlock(struct proc *p, struct mlock_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mlock", kernel_functions[SYS_mlock], r); }
int hook_munlock(struct proc *p, struct munlock_args *u, int *r) { return generic_syscall_log(p, u, "SYS_munlock", kernel_functions[SYS_munlock], r); }
int hook_undelete(struct proc *p, struct undelete_args *u, int *r) { return generic_syscall_log(p, u, "SYS_undelete", kernel_functions[SYS_undelete], r); }
int hook_setattrlist(struct proc *p, struct setattrlist_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setattrlist", kernel_functions[SYS_setattrlist], r); }
int hook_getdirentriesattr(struct proc *p, struct getdirentriesattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getdirentriesattr", kernel_functions[SYS_getdirentriesattr], r); }
int hook_exchangedata(struct proc *p, struct exchangedata_args *u, int *r) { return generic_syscall_log(p, u, "SYS_exchangedata", kernel_functions[SYS_exchangedata], r); }
int hook_searchfs(struct proc *p, struct searchfs_args *u, int *r) { return generic_syscall_log(p, u, "SYS_searchfs", kernel_functions[SYS_searchfs], r); }
int hook_delete(struct proc *p, struct delete_args *u, int *r) { return generic_syscall_log(p, u, "SYS_delete", kernel_functions[SYS_delete], r); }
int hook_copyfile(struct proc *p, struct copyfile_args *u, int *r) { return generic_syscall_log(p, u, "SYS_copyfile", kernel_functions[SYS_copyfile], r); }
int hook_fgetattrlist(struct proc *p, struct fgetattrlist_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fgetattrlist", kernel_functions[SYS_fgetattrlist], r); }
int hook_fsetattrlist(struct proc *p, struct fsetattrlist_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fsetattrlist", kernel_functions[SYS_fsetattrlist], r); }
int hook_poll(struct proc *p, struct poll_args *u, int *r) { return generic_syscall_log(p, u, "SYS_poll", kernel_functions[SYS_poll], r); }
int hook_watchevent(struct proc *p, struct watchevent_args *u, int *r) { return generic_syscall_log(p, u, "SYS_watchevent", kernel_functions[SYS_watchevent], r); }
int hook_waitevent(struct proc *p, struct waitevent_args *u, int *r) { return generic_syscall_log(p, u, "SYS_waitevent", kernel_functions[SYS_waitevent], r); }
int hook_modwatch(struct proc *p, struct modwatch_args *u, int *r) { return generic_syscall_log(p, u, "SYS_modwatch", kernel_functions[SYS_modwatch], r); }
int hook_fgetxattr(struct proc *p, struct fgetxattr_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_fgetxattr", kernel_functions[SYS_fgetxattr], r); }
int hook_setxattr(struct proc *p, struct setxattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setxattr", kernel_functions[SYS_setxattr], r); }
int hook_fsetxattr(struct proc *p, struct fsetxattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fsetxattr", kernel_functions[SYS_fsetxattr], r); }
int hook_removexattr(struct proc *p, struct removexattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_removexattr", kernel_functions[SYS_removexattr], r); }
int hook_fremovexattr(struct proc *p, struct fremovexattr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fremovexattr", kernel_functions[SYS_fremovexattr], r); }
int hook_listxattr(struct proc *p, struct listxattr_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_listxattr", kernel_functions[SYS_listxattr], r); }
int hook_flistxattr(struct proc *p, struct flistxattr_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_flistxattr", kernel_functions[SYS_flistxattr], r); }
int hook_fsctl(struct proc *p, struct fsctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fsctl", kernel_functions[SYS_fsctl], r); }
int hook_initgroups(struct proc *p, struct initgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_initgroups", kernel_functions[SYS_initgroups], r); }
int hook_posix_spawn(struct proc *p, struct posix_spawn_args *u, int *r) { return generic_syscall_log(p, u, "SYS_posix_spawn", kernel_functions[SYS_posix_spawn], r); }
int hook_ffsctl(struct proc *p, struct ffsctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ffsctl", kernel_functions[SYS_ffsctl], r); }
int hook_nfsclnt(struct proc *p, struct nfsclnt_args *u, int *r) { return generic_syscall_log(p, u, "SYS_nfsclnt", kernel_functions[SYS_nfsclnt], r); }
int hook_minherit(struct proc *p, struct minherit_args *u, int *r) { return generic_syscall_log(p, u, "SYS_minherit", kernel_functions[SYS_minherit], r); }
int hook_semsys(struct proc *p, struct semsys_args *u, int *r) { return generic_syscall_log(p, u, "SYS_semsys", kernel_functions[SYS_semsys], r); }
int hook_msgsys(struct proc *p, struct msgsys_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgsys", kernel_functions[SYS_msgsys], r); }
int hook_shmsys(struct proc *p, struct shmsys_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shmsys", kernel_functions[SYS_shmsys], r); }
int hook_semctl(struct proc *p, struct semctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_semctl", kernel_functions[SYS_semctl], r); }
int hook_semget(struct proc *p, struct semget_args *u, int *r) { return generic_syscall_log(p, u, "SYS_semget", kernel_functions[SYS_semget], r); }
int hook_semop(struct proc *p, struct semop_args *u, int *r) { return generic_syscall_log(p, u, "SYS_semop", kernel_functions[SYS_semop], r); }
int hook_msgctl(struct proc *p, struct msgctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgctl", kernel_functions[SYS_msgctl], r); }
int hook_msgget(struct proc *p, struct msgget_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgget", kernel_functions[SYS_msgget], r); }
int hook_msgsnd(struct proc *p, struct msgsnd_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgsnd", kernel_functions[SYS_msgsnd], r); }
int hook_msgrcv(struct proc *p, struct msgrcv_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_msgrcv", kernel_functions[SYS_msgrcv], r); }
int hook_shmat(struct proc *p, struct shmat_args *u, user_addr_t *r) { return generic_syscall_log(p, u, "SYS_shmat", kernel_functions[SYS_shmat], r); }
int hook_shmctl(struct proc *p, struct shmctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shmctl", kernel_functions[SYS_shmctl], r); }
int hook_shmdt(struct proc *p, struct shmdt_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shmdt", kernel_functions[SYS_shmdt], r); }
int hook_shmget(struct proc *p, struct shmget_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shmget", kernel_functions[SYS_shmget], r); }
int hook_shm_open(struct proc *p, struct shm_open_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shm_open", kernel_functions[SYS_shm_open], r); }
int hook_shm_unlink(struct proc *p, struct shm_unlink_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shm_unlink", kernel_functions[SYS_shm_unlink], r); }
int hook_sem_close(struct proc *p, struct sem_close_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_close", kernel_functions[SYS_sem_close], r); }
int hook_sem_unlink(struct proc *p, struct sem_unlink_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_unlink", kernel_functions[SYS_sem_unlink], r); }
int hook_sem_wait(struct proc *p, struct sem_wait_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_wait", kernel_functions[SYS_sem_wait], r); }
int hook_sem_trywait(struct proc *p, struct sem_trywait_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_trywait", kernel_functions[SYS_sem_trywait], r); }
int hook_sem_post(struct proc *p, struct sem_post_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_post", kernel_functions[SYS_sem_post], r); }
int hook_sysctlbyname(struct proc *p, struct sysctlbyname_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sysctlbyname", kernel_functions[SYS_sysctlbyname], r); }
int hook_sem_init(struct proc *p, struct sem_init_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_init", kernel_functions[SYS_sem_init], r); }
int hook_sem_destroy(struct proc *p, struct sem_destroy_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_destroy", kernel_functions[SYS_sem_destroy], r); }
int hook_open_extended(struct proc *p, struct open_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_open_extended", kernel_functions[SYS_open_extended], r); }
int hook_umask_extended(struct proc *p, struct umask_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_umask_extended", kernel_functions[SYS_umask_extended], r); }
int hook_stat_extended(struct proc *p, struct stat_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_stat_extended", kernel_functions[SYS_stat_extended], r); }
int hook_lstat_extended(struct proc *p, struct lstat_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lstat_extended", kernel_functions[SYS_lstat_extended], r); }
int hook_fstat_extended(struct proc *p, struct fstat_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstat_extended", kernel_functions[SYS_fstat_extended], r); }
int hook_chmod_extended(struct proc *p, struct chmod_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chmod_extended", kernel_functions[SYS_chmod_extended], r); }
int hook_fchmod_extended(struct proc *p, struct fchmod_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchmod_extended", kernel_functions[SYS_fchmod_extended], r); }
int hook_access_extended(struct proc *p, struct access_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_access_extended", kernel_functions[SYS_access_extended], r); }
int hook_settid(struct proc *p, struct settid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_settid", kernel_functions[SYS_settid], r); }
int hook_setsgroups(struct proc *p, struct setsgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setsgroups", kernel_functions[SYS_setsgroups], r); }
int hook_getsgroups(struct proc *p, struct getsgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getsgroups", kernel_functions[SYS_getsgroups], r); }
int hook_setwgroups(struct proc *p, struct setwgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setwgroups", kernel_functions[SYS_setwgroups], r); }
int hook_getwgroups(struct proc *p, struct getwgroups_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getwgroups", kernel_functions[SYS_getwgroups], r); }
int hook_mkfifo_extended(struct proc *p, struct mkfifo_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mkfifo_extended", kernel_functions[SYS_mkfifo_extended], r); }
int hook_mkdir_extended(struct proc *p, struct mkdir_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mkdir_extended", kernel_functions[SYS_mkdir_extended], r); }
int hook_identitysvc(struct proc *p, struct identitysvc_args *u, int *r) { return generic_syscall_log(p, u, "SYS_identitysvc", kernel_functions[SYS_identitysvc], r); }
int hook_shared_region_check_np(struct proc *p, struct shared_region_check_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shared_region_check_np", kernel_functions[SYS_shared_region_check_np], r); }
int hook_vm_pressure_monitor(struct proc *p, struct vm_pressure_monitor_args *u, int *r) { return generic_syscall_log(p, u, "SYS_vm_pressure_monitor", kernel_functions[SYS_vm_pressure_monitor], r); }
int hook_psynch_rw_longrdlock(struct proc *p, struct psynch_rw_longrdlock_args *u, uint32_t *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_longrdlock", kernel_functions[SYS_psynch_rw_longrdlock], r); }
int hook_psynch_rw_yieldwrlock(struct proc *p, struct psynch_rw_yieldwrlock_args *u, uint32_t *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_yieldwrlock", kernel_functions[SYS_psynch_rw_yieldwrlock], r); }
int hook_psynch_rw_downgrade(struct proc *p, struct psynch_rw_downgrade_args *u, int *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_downgrade", kernel_functions[SYS_psynch_rw_downgrade], r); }
int hook_psynch_rw_upgrade(struct proc *p, struct psynch_rw_upgrade_args *u, uint32_t *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_upgrade", kernel_functions[SYS_psynch_rw_upgrade], r); }
int hook_psynch_rw_unlock2(struct proc *p, struct psynch_rw_unlock2_args *u, uint32_t *r) { return generic_syscall_log(p, u, "SYS_psynch_rw_unlock2", kernel_functions[SYS_psynch_rw_unlock2], r); }
int hook_getsid(struct proc *p, struct getsid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getsid", kernel_functions[SYS_getsid], r); }
int hook_settid_with_pid(struct proc *p, struct settid_with_pid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_settid_with_pid", kernel_functions[SYS_settid_with_pid], r); }
int hook_psynch_cvclrprepost(struct proc *p, struct psynch_cvclrprepost_args *u, int *r) { return generic_syscall_log(p, u, "SYS_psynch_cvclrprepost", kernel_functions[SYS_psynch_cvclrprepost], r); }
int hook_aio_fsync(struct proc *p, struct aio_fsync_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_fsync", kernel_functions[SYS_aio_fsync], r); }
int hook_aio_return(struct proc *p, struct aio_return_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_aio_return", kernel_functions[SYS_aio_return], r); }
int hook_aio_suspend(struct proc *p, struct aio_suspend_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_suspend", kernel_functions[SYS_aio_suspend], r); }
int hook_aio_cancel(struct proc *p, struct aio_cancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_cancel", kernel_functions[SYS_aio_cancel], r); }
int hook_aio_error(struct proc *p, struct aio_error_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_error", kernel_functions[SYS_aio_error], r); }
int hook_aio_read(struct proc *p, struct aio_read_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_read", kernel_functions[SYS_aio_read], r); }
int hook_aio_write(struct proc *p, struct aio_write_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_write", kernel_functions[SYS_aio_write], r); }
int hook_lio_listio(struct proc *p, struct lio_listio_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lio_listio", kernel_functions[SYS_lio_listio], r); }
int hook_process_policy(struct proc *p, struct process_policy_args *u, int *r) { return generic_syscall_log(p, u, "SYS_process_policy", kernel_functions[SYS_process_policy], r); }
int hook_mlockall(struct proc *p, struct mlockall_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mlockall", kernel_functions[SYS_mlockall], r); }
int hook_munlockall(struct proc *p, struct munlockall_args *u, int *r) { return generic_syscall_log(p, u, "SYS_munlockall", kernel_functions[SYS_munlockall], r); }
int hook___pthread_kill(struct proc *p, struct __pthread_kill_args *u, int *r) { return generic_syscall_log(p, u, "SYS___pthread_kill", kernel_functions[SYS___pthread_kill], r); }
int hook___sigwait(struct proc *p, struct __sigwait_args *u, int *r) { return generic_syscall_log(p, u, "SYS___sigwait", kernel_functions[SYS___sigwait], r); }
int hook___pthread_markcancel(struct proc *p, struct __pthread_markcancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS___pthread_markcancel", kernel_functions[SYS___pthread_markcancel], r); }
int hook_sendfile(struct proc *p, struct sendfile_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendfile", kernel_functions[SYS_sendfile], r); }
int hook_stat64(struct proc *p, struct stat64_args *u, int *r){ return generic_syscall_log(p, u, "SYS_stat64", kernel_functions[SYS_stat64], r); }
int hook_stat64_extended(struct proc *p, struct stat64_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_stat64_extended", kernel_functions[SYS_stat64_extended], r); }
int hook_lstat64_extended(struct proc *p, struct lstat64_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lstat64_extended", kernel_functions[SYS_lstat64_extended], r); }
int hook_fstat64_extended(struct proc *p, struct fstat64_extended_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstat64_extended", kernel_functions[SYS_fstat64_extended], r); }
int hook_audit(struct proc *p, struct audit_args *u, int *r) { return generic_syscall_log(p, u, "SYS_audit", kernel_functions[SYS_audit], r); }
int hook_auditon(struct proc *p, struct auditon_args *u, int *r) { return generic_syscall_log(p, u, "SYS_auditon", kernel_functions[SYS_auditon], r); }
int hook_getauid(struct proc *p, struct getauid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getauid", kernel_functions[SYS_getauid], r); }
int hook_setauid(struct proc *p, struct setauid_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setauid", kernel_functions[SYS_setauid], r); }
int hook_setaudit_addr(struct proc *p, struct setaudit_addr_args *u, int *r) { return generic_syscall_log(p, u, "SYS_setaudit_addr", kernel_functions[SYS_setaudit_addr], r); }
int hook_auditctl(struct proc *p, struct auditctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_auditctl", kernel_functions[SYS_auditctl], r); }
int hook_lchown(struct proc *p, struct lchown_args *u, int *r) { return generic_syscall_log(p, u, "SYS_lchown", kernel_functions[SYS_lchown], r); }
int hook_stack_snapshot(struct proc *p, struct stack_snapshot_args *u, int *r) { return generic_syscall_log(p, u, "SYS_stack_snapshot", kernel_functions[SYS_stack_snapshot], r); }
int hook___mac_execve(struct proc *p, struct __mac_execve_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_execve", kernel_functions[SYS___mac_execve], r); }
int hook___mac_syscall(struct proc *p, struct __mac_syscall_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_syscall", kernel_functions[SYS___mac_syscall], r); }
int hook___mac_get_file(struct proc *p, struct __mac_get_file_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_file", kernel_functions[SYS___mac_get_file], r); }
int hook___mac_set_file(struct proc *p, struct __mac_set_file_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_file", kernel_functions[SYS___mac_set_file], r); }
int hook___mac_get_link(struct proc *p, struct __mac_get_link_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_link", kernel_functions[SYS___mac_get_link], r); }
int hook___mac_set_link(struct proc *p, struct __mac_set_link_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_link", kernel_functions[SYS___mac_set_link], r); }
int hook___mac_get_proc(struct proc *p, struct __mac_get_proc_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_proc", kernel_functions[SYS___mac_get_proc], r); }
int hook___mac_set_proc(struct proc *p, struct __mac_set_proc_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_proc", kernel_functions[SYS___mac_set_proc], r); }
int hook___mac_get_fd(struct proc *p, struct __mac_get_fd_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_fd", kernel_functions[SYS___mac_get_fd], r); }
int hook___mac_set_fd(struct proc *p, struct __mac_set_fd_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_fd", kernel_functions[SYS___mac_set_fd], r); }
int hook___mac_get_pid(struct proc *p, struct __mac_get_pid_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_pid", kernel_functions[SYS___mac_get_pid], r); }
int hook___mac_get_lcid(struct proc *p, struct __mac_get_lcid_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_lcid", kernel_functions[SYS___mac_get_lcid], r); }
int hook___mac_get_lctx(struct proc *p, struct __mac_get_lctx_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_lctx", kernel_functions[SYS___mac_get_lctx], r); }
int hook___mac_set_lctx(struct proc *p, struct __mac_set_lctx_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_set_lctx", kernel_functions[SYS___mac_set_lctx], r); }
int hook_pselect(struct proc *p, struct pselect_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pselect", kernel_functions[SYS_pselect], r); }
int hook_pselect_nocancel(struct proc *p, struct pselect_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pselect_nocancel", kernel_functions[SYS_pselect_nocancel], r); }
int hook_wait4_nocancel(struct proc *p, struct wait4_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_wait4_nocancel", kernel_functions[SYS_wait4_nocancel], r); }
int hook_recvmsg_nocancel(struct proc *p, struct recvmsg_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_recvmsg_nocancel", kernel_functions[SYS_recvmsg_nocancel], r); }
int hook_sendmsg_nocancel(struct proc *p, struct sendmsg_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendmsg_nocancel", kernel_functions[SYS_sendmsg_nocancel], r); }
int hook_recvfrom_nocancel(struct proc *p, struct recvfrom_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_recvfrom_nocancel", kernel_functions[SYS_recvfrom_nocancel], r); }
int hook_accept_nocancel(struct proc *p, struct accept_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_accept_nocancel", kernel_functions[SYS_accept_nocancel], r); }
int hook_msync_nocancel(struct proc *p, struct msync_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msync_nocancel", kernel_functions[SYS_msync_nocancel], r); }
int hook_select_nocancel(struct proc *p, struct select_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_select_nocancel", kernel_functions[SYS_select_nocancel], r); }
int hook_fsync_nocancel(struct proc *p, struct fsync_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fsync_nocancel", kernel_functions[SYS_fsync_nocancel], r); }
int hook_connect_nocancel(struct proc *p, struct connect_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_connect_nocancel", kernel_functions[SYS_connect_nocancel], r); }
int hook_sigsuspend_nocancel(struct proc *p, struct sigsuspend_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sigsuspend_nocancel", kernel_functions[SYS_sigsuspend_nocancel], r); }
int hook_readv_nocancel(struct proc *p, struct readv_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_readv_nocancel", kernel_functions[SYS_readv_nocancel], r); }
int hook_writev_nocancel(struct proc *p, struct writev_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_writev_nocancel", kernel_functions[SYS_writev_nocancel], r); }
int hook_sendto_nocancel(struct proc *p, struct sendto_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendto_nocancel", kernel_functions[SYS_sendto_nocancel], r); }
int hook_pread_nocancel(struct proc *p, struct pread_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_pread_nocancel", kernel_functions[SYS_pread_nocancel], r); }
int hook_pwrite_nocancel(struct proc *p, struct pwrite_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_pwrite_nocancel", kernel_functions[SYS_pwrite_nocancel], r); }
int hook_waitid_nocancel(struct proc *p, struct waitid_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_waitid_nocancel", kernel_functions[SYS_waitid_nocancel], r); }
int hook_poll_nocancel(struct proc *p, struct poll_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_poll_nocancel", kernel_functions[SYS_poll_nocancel], r); }
int hook_msgsnd_nocancel(struct proc *p, struct msgsnd_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_msgsnd_nocancel", kernel_functions[SYS_msgsnd_nocancel], r); }
int hook_msgrcv_nocancel(struct proc *p, struct msgrcv_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_msgrcv_nocancel", kernel_functions[SYS_msgrcv_nocancel], r); }
int hook_sem_wait_nocancel(struct proc *p, struct sem_wait_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sem_wait_nocancel", kernel_functions[SYS_sem_wait_nocancel], r); }
int hook_aio_suspend_nocancel(struct proc *p, struct aio_suspend_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_aio_suspend_nocancel", kernel_functions[SYS_aio_suspend_nocancel], r); }
int hook___sigwait_nocancel(struct proc *p, struct __sigwait_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS___sigwait_nocancel", kernel_functions[SYS___sigwait_nocancel], r); }
int hook___semwait_signal_nocancel(struct proc *p, struct __semwait_signal_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS___semwait_signal_nocancel", kernel_functions[SYS___semwait_signal_nocancel], r); }
int hook___mac_mount(struct proc *p, struct __mac_mount_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_mount", kernel_functions[SYS___mac_mount], r); }
int hook___mac_get_mount(struct proc *p, struct __mac_get_mount_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_get_mount", kernel_functions[SYS___mac_get_mount], r); }
int hook___mac_getfsstat(struct proc *p, struct __mac_getfsstat_args *u, int *r) { return generic_syscall_log(p, u, "SYS___mac_getfsstat", kernel_functions[SYS___mac_getfsstat], r); }
int hook_audit_session_self(struct proc *p, struct audit_session_self_args *u, mach_port_name_t *r) { return generic_syscall_log(p, u, "SYS_audit_session_self", kernel_functions[SYS_audit_session_self], r); }
int hook_audit_session_join(struct proc *p, struct audit_session_join_args *u, int *r) { return generic_syscall_log(p, u, "SYS_audit_session_join", kernel_functions[SYS_audit_session_join], r); }
int hook_fileport_makeport(struct proc *p, struct fileport_makeport_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fileport_makeport", kernel_functions[SYS_fileport_makeport], r); }
int hook_fileport_makefd(struct proc *p, struct fileport_makefd_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fileport_makefd", kernel_functions[SYS_fileport_makefd], r); }
int hook_audit_session_port(struct proc *p, struct audit_session_port_args *u, int *r) { return generic_syscall_log(p, u, "SYS_audit_session_port", kernel_functions[SYS_audit_session_port], r); }
int hook_pid_suspend(struct proc *p, struct pid_suspend_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pid_suspend", kernel_functions[SYS_pid_suspend], r); }
int hook_pid_resume(struct proc *p, struct pid_resume_args *u, int *r) { return generic_syscall_log(p, u, "SYS_pid_resume", kernel_functions[SYS_pid_resume], r); }
int hook_shared_region_map_and_slide_np(struct proc *p, struct shared_region_map_and_slide_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_shared_region_map_and_slide_np", kernel_functions[SYS_shared_region_map_and_slide_np], r); }
int hook_kas_info(struct proc *p, struct kas_info_args *u, int *r) { return generic_syscall_log(p, u, "SYS_kas_info", kernel_functions[SYS_kas_info], r); }
int hook_ioctl(struct proc *p, struct ioctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ioctl", kernel_functions[SYS_ioctl], r); }
int hook_guarded_open_np(struct proc *p, struct guarded_open_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_guarded_open_np", kernel_functions[SYS_guarded_open_np], r); }
int hook_bsdthread_create(struct proc *p, struct bsdthread_create_args *u, user_addr_t *r) {
    return generic_syscall_log(p, u, "SYS_bsdthread_create", kernel_functions[SYS_bsdthread_create], r);
}

/**** UPDATE  ****/
int hook_connectx(struct proc *p, struct connectx_args *u, int *r) { return generic_syscall_log(p, u, "SYS_connectx", kernel_functions[SYS_connectx], r); }
int hook_disconnectx(struct proc *p, struct disconnectx_args *u, int *r) { return generic_syscall_log(p, u, "SYS_disconnectx", kernel_functions[SYS_disconnectx], r); }
int hook_peeloff(struct proc *p, struct peeloff_args *u, int *r) { return generic_syscall_log(p, u, "SYS_peeloff", kernel_functions[SYS_peeloff], r); }
int hook_socket_delegate(struct proc *p, struct socket_delegate_args *u, int *r) { return generic_syscall_log(p, u, "SYS_socket_delegate", kernel_functions[SYS_socket_delegate], r); }
int hook_telemetry(struct proc *p, struct telemetry_args *u, int *r) { return generic_syscall_log(p, u, "SYS_telemetry", kernel_functions[SYS_telemetry], r); }
int hook_proc_uuid_policy(struct proc *p, struct proc_uuid_policy_args *u, int *r) { return generic_syscall_log(p, u, "SYS_proc_uuid_policy", kernel_functions[SYS_proc_uuid_policy], r); }
int hook_memorystatus_get_level(struct proc *p, struct memorystatus_get_level_args *u, int *r) { return generic_syscall_log(p, u, "SYS_memorystatus_get_level", kernel_functions[SYS_memorystatus_get_level], r); }
int hook_system_override(struct proc *p, struct system_override_args *u, int *r) { return generic_syscall_log(p, u, "SYS_system_override", kernel_functions[SYS_system_override], r); }
int hook_vfs_purge(struct proc *p, struct vfs_purge_args *u, int *r) { return generic_syscall_log(p, u, "SYS_vfs_purge", kernel_functions[SYS_vfs_purge], r); }
int hook_sfi_ctl(struct proc *p, struct sfi_ctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sfi_ctl", kernel_functions[SYS_sfi_ctl], r); }
int hook_sfi_pidctl(struct proc *p, struct sfi_pidctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sfi_pidctl", kernel_functions[SYS_sfi_pidctl], r); }
int hook_coalition(struct proc *p, struct coalition_args *u, int *r) { return generic_syscall_log(p, u, "SYS_coalition", kernel_functions[SYS_coalition], r); }
int hook_coalition_info(struct proc *p, struct coalition_info_args *u, int *r) { return generic_syscall_log(p, u, "SYS_coalition_info", kernel_functions[SYS_coalition_info], r); }
int hook_necp_match_policy(struct proc *p, struct necp_match_policy_args *u, int *r) { return generic_syscall_log(p, u, "SYS_necp_match_policy", kernel_functions[SYS_necp_match_policy], r); }
int hook_getattrlistbulk(struct proc *p, struct getattrlistbulk_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getattrlistbulk", kernel_functions[SYS_getattrlistbulk], r); }
int hook_clonefileat(struct proc *p, struct clonefileat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_clonefileat", kernel_functions[SYS_clonefileat], r); }
int hook_openat(struct proc *p, struct openat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_openat", kernel_functions[SYS_openat], r); }
int hook_openat_nocancel(struct proc *p, struct openat_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_openat_nocancel", kernel_functions[SYS_openat_nocancel], r); }
int hook_renameat(struct proc *p, struct renameat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_renameat", kernel_functions[SYS_renameat], r); }
int hook_faccessat(struct proc *p, struct faccessat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_faccessat", kernel_functions[SYS_faccessat], r); }
int hook_fchmodat(struct proc *p, struct fchmodat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchmodat", kernel_functions[SYS_fchmodat], r); }
int hook_fchownat(struct proc *p, struct fchownat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fchownat", kernel_functions[SYS_fchownat], r); }
int hook_fstatat(struct proc *p, struct fstatat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstatat", kernel_functions[SYS_fstatat], r); }
int hook_fstatat64(struct proc *p, struct fstatat64_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fstatat64", kernel_functions[SYS_fstatat64], r); }
int hook_linkat(struct proc *p, struct linkat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_linkat", kernel_functions[SYS_linkat], r); }
int hook_unlinkat(struct proc *p, struct unlinkat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_unlinkat", kernel_functions[SYS_unlinkat], r); }
int hook_readlinkat(struct proc *p, struct readlinkat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_readlinkat", kernel_functions[SYS_readlinkat], r); }
int hook_symlinkat(struct proc *p, struct symlinkat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_symlinkat", kernel_functions[SYS_symlinkat], r); }
int hook_mkdirat(struct proc *p, struct mkdirat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mkdirat", kernel_functions[SYS_mkdirat], r); }
int hook_getattrlistat(struct proc *p, struct getattrlistat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getattrlistat", kernel_functions[SYS_getattrlistat], r); }
int hook_proc_trace_log(struct proc *p, struct proc_trace_log_args *u, int *r) { return generic_syscall_log(p, u, "SYS_proc_trace_log", kernel_functions[SYS_proc_trace_log], r); }
int hook_bsdthread_ctl(struct proc *p, struct bsdthread_ctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_bsdthread_ctl", kernel_functions[SYS_bsdthread_ctl], r); }
int hook_openbyid_np(struct proc *p, struct openbyid_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_openbyid_np", kernel_functions[SYS_openbyid_np], r); }
int hook_recvmsg_x(struct proc *p, struct recvmsg_x_args *u, int *r) { return generic_syscall_log(p, u, "SYS_recvmsg_x", kernel_functions[SYS_recvmsg_x], r); }
int hook_sendmsg_x(struct proc *p, struct sendmsg_x_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendmsg_x", kernel_functions[SYS_sendmsg_x], r); }
int hook_thread_selfusage(struct proc *p, struct thread_selfusage_args *u, int *r) { return generic_syscall_log(p, u, "SYS_thread_selfusage", kernel_functions[SYS_thread_selfusage], r); }
int hook_csrctl(struct proc *p, struct csrctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_csrctl", kernel_functions[SYS_csrctl], r); }
int hook_guarded_open_dprotected_np(struct proc *p, struct guarded_open_dprotected_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_guarded_open_dprotected_np", kernel_functions[SYS_guarded_open_dprotected_np], r); }
int hook_guarded_write_np(struct proc *p, struct guarded_write_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_guarded_write_np", kernel_functions[SYS_guarded_write_np], r); }
int hook_guarded_pwrite_np(struct proc *p, struct guarded_pwrite_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_guarded_pwrite_np", kernel_functions[SYS_guarded_pwrite_np], r); }
int hook_guarded_writev_np(struct proc *p, struct guarded_writev_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_guarded_writev_np", kernel_functions[SYS_guarded_writev_np], r); }
int hook_renameatx_np(struct proc *p, struct renameatx_np_args *u, int *r) { return generic_syscall_log(p, u, "SYS_renameatx_np", kernel_functions[SYS_renameatx_np], r); }
int hook_mremap_encrypted(struct proc *p, struct mremap_encrypted_args *u, int *r) { return generic_syscall_log(p, u, "SYS_mremap_encrypted", kernel_functions[SYS_mremap_encrypted], r); }
int hook_netagent_trigger(struct proc *p, struct netagent_trigger_args *u, int *r) { return generic_syscall_log(p, u, "SYS_netagent_trigger", kernel_functions[SYS_netagent_trigger], r); }
int hook_stack_snapshot_with_config(struct proc *p, struct stack_snapshot_with_config_args *u, int *r) { return generic_syscall_log(p, u, "SYS_stack_snapshot_with_config", kernel_functions[SYS_stack_snapshot_with_config], r); }
int hook_microstackshot(struct proc *p, struct microstackshot_args *u, int *r) { return generic_syscall_log(p, u, "SYS_microstackshot", kernel_functions[SYS_microstackshot], r); }
int hook_grab_pgo_data(struct proc *p, struct grab_pgo_data_args *u, int *r) { return generic_syscall_log(p, u, "SYS_grab_pgo_data", kernel_functions[SYS_grab_pgo_data], r); }
int hook_persona(struct proc *p, struct persona_args *u, int *r) { return generic_syscall_log(p, u, "SYS_persona", kernel_functions[SYS_persona], r); }
int hook_work_interval_ctl(struct proc *p, struct work_interval_ctl_args *u, int *r) { return generic_syscall_log(p, u, "SYS_work_interval_ctl", kernel_functions[SYS_work_interval_ctl], r); }
int hook_getentropy(struct proc *p, struct getentropy_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getentropy", kernel_functions[SYS_getentropy], r); }
int hook_necp_open(struct proc *p, struct necp_open_args *u, int *r) { return generic_syscall_log(p, u, "SYS_necp_open", kernel_functions[SYS_necp_open], r); }
int hook_necp_client_action(struct proc *p, struct necp_client_action_args *u, int *r) { return generic_syscall_log(p, u, "SYS_necp_client_action", kernel_functions[SYS_necp_client_action], r); }
//int hook___nexus_open(struct proc *p, struct __nexus_open_args *u, int *r) { return generic_syscall_log(p, u, "SYS___nexus_open", kernel_functions[SYS___nexus_open], r); }
//int hook___nexus_register(struct proc *p, struct __nexus_register_args *u, int *r) { return generic_syscall_log(p, u, "SYS___nexus_register", kernel_functions[SYS___nexus_register], r); }
//int hook___nexus_deregister(struct proc *p, struct __nexus_deregister_args *u, int *r) { return generic_syscall_log(p, u, "SYS___nexus_deregister", kernel_functions[SYS___nexus_deregister], r); }
//int hook___nexus_create(struct proc *p, struct __nexus_create_args *u, int *r) { return generic_syscall_log(p, u, "SYS___nexus_create", kernel_functions[SYS___nexus_create], r); }
//int hook___nexus_destroy(struct proc *p, struct __nexus_destroy_args *u, int *r) { return generic_syscall_log(p, u, "SYS___nexus_destroy", kernel_functions[SYS___nexus_destroy], r); }
//int hook___nexus_get_opt(struct proc *p, struct __nexus_get_opt_args *u, int *r) { return generic_syscall_log(p, u, "SYS___nexus_get_opt", kernel_functions[SYS___nexus_get_opt], r); }
//int hook___nexus_set_opt(struct proc *p, struct __nexus_set_opt_args *u, int *r) { return generic_syscall_log(p, u, "SYS___nexus_set_opt", kernel_functions[SYS___nexus_set_opt], r); }
//int hook___channel_open(struct proc *p, struct __channel_open_args *u, int *r) { return generic_syscall_log(p, u, "SYS___channel_open", kernel_functions[SYS___channel_open], r); }
//int hook___channel_get_info(struct proc *p, struct __channel_get_info_args *u, int *r) { return generic_syscall_log(p, u, "SYS___channel_get_info", kernel_functions[SYS___channel_get_info], r); }
//int hook___channel_sync(struct proc *p, struct __channel_sync_args *u, int *r) { return generic_syscall_log(p, u, "SYS___channel_sync", kernel_functions[SYS___channel_sync], r); }
//int hook___channel_get_opt(struct proc *p, struct __channel_get_opt_args *u, int *r) { return generic_syscall_log(p, u, "SYS___channel_get_opt", kernel_functions[SYS___channel_get_opt], r); }
//int hook___channel_set_opt(struct proc *p, struct __channel_set_opt_args *u, int *r) { return generic_syscall_log(p, u, "SYS___channel_set_opt", kernel_functions[SYS___channel_set_opt], r); }
int hook_ulock_wait(struct proc *p, struct ulock_wait_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ulock_wait", kernel_functions[SYS_ulock_wait], r); }
int hook_ulock_wake(struct proc *p, struct ulock_wake_args *u, int *r) { return generic_syscall_log(p, u, "SYS_ulock_wake", kernel_functions[SYS_ulock_wake], r); }
int hook_fclonefileat(struct proc *p, struct fclonefileat_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fclonefileat", kernel_functions[SYS_fclonefileat], r); }
int hook_fs_snapshot(struct proc *p, struct fs_snapshot_args *u, int *r) { return generic_syscall_log(p, u, "SYS_fs_snapshot", kernel_functions[SYS_fs_snapshot], r); }
int hook_terminate_with_payload(struct proc *p, struct terminate_with_payload_args *u, int *r) { return generic_syscall_log(p, u, "SYS_terminate_with_payload", kernel_functions[SYS_terminate_with_payload], r); }
int hook_abort_with_payload(struct proc *p, struct abort_with_payload_args *u, int *r) { return generic_syscall_log(p, u, "SYS_abort_with_payload", kernel_functions[SYS_abort_with_payload], r); }


int hook_accept(struct proc *p, struct accept_args *u, int *r) { return generic_syscall_log(p, u, "SYS_accept", kernel_functions[SYS_accept], r); }
int hook_chdir(struct proc *p, struct chdir_args *u, int *r) { return generic_syscall_log(p, u, "SYS_chdir", kernel_functions[SYS_chdir], r); }
int hook_close(struct proc *p, struct close_args *u, int *r) { return generic_syscall_log(p, u, "SYS_close", kernel_functions[SYS_close], r); }
int hook_close_nocancel(struct proc *p, struct close_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_close_nocancel", kernel_functions[SYS_close_nocancel], r); }
int hook_dup(struct proc *p, struct dup_args *u, int *r) { return generic_syscall_log(p, u, "SYS_dup", kernel_functions[SYS_dup], r); }
int hook_getpeername(struct proc *p, struct getpeername_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getpeername", kernel_functions[SYS_getpeername], r); }
int hook_getsockname(struct proc *p, struct getsockname_args *u, int *r) { return generic_syscall_log(p, u, "SYS_getsockname", kernel_functions[SYS_getsockname], r); }
int hook_kill(struct proc *p, struct kill_args *u, int *r) { return generic_syscall_log(p, u, "SYS_kill", kernel_functions[SYS_kill], r); }
int hook_open_nocancel(struct proc *p, struct open_nocancel_args *u, int *r) { return generic_syscall_log(p, u, "SYS_open_nocancel", kernel_functions[SYS_open_nocancel], r); }
int hook_read_nocancel(struct proc *p, struct read_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_read_nocancel", kernel_functions[SYS_read_nocancel], r); }
int hook_recvfrom(struct proc *p, struct recvfrom_args *u, int *r) { return generic_syscall_log(p, u, "SYS_recvfrom", kernel_functions[SYS_recvfrom], r); }
int hook_recvmsg(struct proc *p, struct recvmsg_args *u, int *r) { return generic_syscall_log(p, u, "SYS_recvmsg", kernel_functions[SYS_recvmsg], r); }
int hook_sendmsg(struct proc *p, struct sendmsg_args *u, int *r) { return generic_syscall_log(p, u, "SYS_sendmsg", kernel_functions[SYS_sendmsg], r); }
int hook_write_nocancel(struct proc *p, struct write_nocancel_args *u, user_ssize_t *r) { return generic_syscall_log(p, u, "SYS_write_nocancel", kernel_functions[SYS_write_nocancel], r); }
