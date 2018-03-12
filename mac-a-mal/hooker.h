//
//  hooker.h
//  Based on vivami 2015 - mac-a-mal legacy
//
//  Hooks all the relevant system calls and logs them to system.log for later analysis.
//
//  Pham Duy Phuc 2017

#ifndef hookehook_h
#define hookehook_h

#include <mach/mach_types.h>
#include <sys/param.h>
#include <sys/proc.h>

#include "kernel_control.h"

#include "my_data_definitions.h"
#include "syscall.h"
#include "sysproto.h"

#define PT_ATTACH               10
#define PT_DENY_ATTACH          31
#define P_LNOATTACH     0x00001000
#define P_LTRACED       0x00000400

typedef uint32_t csr_config_t;

/* Rootless configuration flags */
#define CSR_ALLOW_UNTRUSTED_KEXTS		(1 << 0)	// 1
#define CSR_ALLOW_UNRESTRICTED_FS		(1 << 1)	// 2
#define CSR_ALLOW_TASK_FOR_PID			(1 << 2)	// 4
#define CSR_ALLOW_KERNEL_DEBUGGER		(1 << 3)	// 8
#define CSR_ALLOW_APPLE_INTERNAL		(1 << 4)	// 16
#define CSR_ALLOW_UNRESTRICTED_DTRACE	(1 << 5)	// 32
#define CSR_ALLOW_UNRESTRICTED_NVRAM	(1 << 6)	// 64

#define CSR_VALID_FLAGS (CSR_ALLOW_UNTRUSTED_KEXTS | \
CSR_ALLOW_UNRESTRICTED_FS | \
CSR_ALLOW_TASK_FOR_PID | \
CSR_ALLOW_KERNEL_DEBUGGER | \
CSR_ALLOW_APPLE_INTERNAL | \
CSR_ALLOW_UNRESTRICTED_DTRACE | \
CSR_ALLOW_UNRESTRICTED_NVRAM)

/* Syscalls */

kern_return_t hook_all_syscalls(void *sysent_addr);
kern_return_t unhook_all_syscalls(void *sysent_addr);

void SEND_INFO(pid_t, const char * format, ... );

/* monitoring functions */
//int hook_read(struct proc *, struct read_args *, user_ssize_t *);
int hook_nosys(struct proc *, struct nosys_args *, int *);
void hook_exit(struct proc *, struct exit_args *, int32_t *);
int hook_fork(struct proc *, struct fork_args *, int *);
int hook_read(struct proc *, struct read_args *, user_ssize_t *);
int hook_write(struct proc *, struct write_args *, user_ssize_t *);
int hook_open(struct proc *, struct open_args *, int *);
int hook_close(struct proc *, struct close_args *, int *);
int hook_wait4(struct proc *, struct wait4_args *, int *);
int hook_link(struct proc *, struct link_args *, int *);
int hook_unlink(struct proc *, struct unlink_args *, int *);
int hook_chdir(struct proc *, struct chdir_args *, int *);
int hook_fchdir(struct proc *, struct fchdir_args *, int *);
int hook_mknod(struct proc *, struct mknod_args *, int *);
int hook_chmod(struct proc *, struct chmod_args *, int *);
int hook_chown(struct proc *, struct chown_args *, int *);
int hook_getfsstat(struct proc *, struct getfsstat_args *, int *);
int hook_getpid(struct proc *, struct getpid_args *, int *);
int hook_setuid(struct proc *, struct setuid_args *, int *);
int hook_getuid(struct proc *, struct getuid_args *, int *);
int hook_geteuid(struct proc *, struct geteuid_args *, int *);
int hook_ptrace(struct proc *, struct ptrace_args *, int *);
int hook_recvmsg(struct proc *, struct recvmsg_args *, int *);
int hook_sendmsg(struct proc *, struct sendmsg_args *, int *);
int hook_recvfrom(struct proc *, struct recvfrom_args *, int *);
int hook_accept(struct proc *, struct accept_args *, int *);
int hook_getpeername(struct proc *, struct getpeername_args *, int *);
int hook_getsockname(struct proc *, struct getsockname_args *, int *);
int hook_access(struct proc *, struct access_args *, int *);
int hook_chflags(struct proc *, struct chflags_args *, int *);
int hook_fchflags(struct proc *, struct fchflags_args *, int *);
int hook_sync(struct proc *, struct sync_args *, int *);
int hook_kill(struct proc *, struct kill_args *, int *);
int hook_getppid(struct proc *, struct getppid_args *, int *);
int hook_dup(struct proc *, struct dup_args *, int *);
int hook_pipe(struct proc *, struct pipe_args *, int *);
int hook_getegid(struct proc *, struct getegid_args *, int *);
int hook_sigaction(struct proc *, struct sigaction_args *, int *);
int hook_getgid(struct proc *, struct getgid_args *, int *);
int hook_sigprocmask(struct proc *, struct sigprocmask_args *, int *);
int hook_getlogin(struct proc *, struct getlogin_args *, int *);
int hook_setlogin(struct proc *, struct setlogin_args *, int *);
int hook_acct(struct proc *, struct acct_args *, int *);
int hook_sigpending(struct proc *, struct sigpending_args *, int *);
int hook_sigaltstack(struct proc *, struct sigaltstack_args *, int *);
int hook_ioctl(struct proc *, struct ioctl_args *, int *);
int hook_reboot(struct proc *, struct reboot_args *, int *);
int hook_revoke(struct proc *, struct revoke_args *, int *);
int hook_symlink(struct proc *, struct symlink_args *, int *);
int hook_readlink(struct proc *, struct readlink_args *, int *);
int hook_execve(struct proc *, struct execve_args *, int *);
int hook_umask(struct proc *, struct umask_args *, int *);
int hook_chroot(struct proc *, struct chroot_args *, int *);
int hook_msync(struct proc *, struct msync_args *, int *);
int hook_vfork(struct proc *, struct vfork_args *, int *);
int hook_munmap(struct proc *, struct munmap_args *, int *);
int hook_mprotect(struct proc *, struct mprotect_args *, int *);
int hook_madvise(struct proc *, struct madvise_args *, int *);
int hook_mincore(struct proc *, struct mincore_args *, int *);
int hook_getgroups(struct proc *, struct getgroups_args *, int *);
int hook_setgroups(struct proc *, struct setgroups_args *, int *);
int hook_getpgrp(struct proc *, struct getpgrp_args *, int *);
int hook_setpgid(struct proc *, struct setpgid_args *, int *);
int hook_setitimer(struct proc *, struct setitimer_args *, int *);
int hook_swapon(struct proc *, struct swapon_args *, int *);
int hook_getitimer(struct proc *, struct getitimer_args *, int *);
int hook_getdtablesize(struct proc *, struct getdtablesize_args *, int *);
int hook_dup2(struct proc *, struct dup2_args *, int *);
int hook_fcntl(struct proc *, struct fcntl_args *, int *);
int hook_select(struct proc *, struct select_args *, int *);
int hook_fsync(struct proc *, struct fsync_args *, int *);
int hook_setpriority(struct proc *, struct setpriority_args *, int *);
int hook_socket(struct proc *, struct socket_args *, int *);
int hook_connect(struct proc *, struct connect_args *, int *);
int hook_getpriority(struct proc *, struct getpriority_args *, int *);
int hook_bind(struct proc *, struct bind_args *, int *);
int hook_setsockopt(struct proc *, struct setsockopt_args *, int *);
int hook_listen(struct proc *, struct listen_args *, int *);
int hook_sigsuspend(struct proc *, struct sigsuspend_args *, int *);
int hook_gettimeofday(struct proc *, struct gettimeofday_args *, int *);
int hook_getrusage(struct proc *, struct getrusage_args *, int *);
int hook_getsockopt(struct proc *, struct getsockopt_args *, int *);
int hook_readv(struct proc *, struct readv_args *, user_ssize_t *);
int hook_writev(struct proc *, struct writev_args *, user_ssize_t *);
int hook_settimeofday(struct proc *, struct settimeofday_args *, int *);
int hook_fchown(struct proc *, struct fchown_args *, int *);
int hook_fchmod(struct proc *, struct fchmod_args *, int *);
int hook_setreuid(struct proc *, struct setreuid_args *, int *);
int hook_setregid(struct proc *, struct setregid_args *, int *);
int hook_rename(struct proc *, struct rename_args *, int *);
int hook_flock(struct proc *, struct flock_args *, int *);
int hook_mkfifo(struct proc *, struct mkfifo_args *, int *);
int hook_sendto(struct proc *, struct sendto_args *, int *);
int hook_shutdown(struct proc *, struct shutdown_args *, int *);
int hook_socketpair(struct proc *, struct socketpair_args *, int *);
int hook_mkdir(struct proc *, struct mkdir_args *, int *);
int hook_rmdir(struct proc *, struct rmdir_args *, int *);
int hook_utimes(struct proc *, struct utimes_args *, int *);
int hook_futimes(struct proc *, struct futimes_args *, int *);
int hook_adjtime(struct proc *, struct adjtime_args *, int *);
int hook_gethostuuid(struct proc *, struct gethostuuid_args *, int *);
int hook_setsid(struct proc *, struct setsid_args *, int *);
int hook_getpgid(struct proc *, struct getpgid_args *, int *);
int hook_setprivexec(struct proc *, struct setprivexec_args *, int *);
int hook_pread(struct proc *, struct pread_args *, user_ssize_t *);
int hook_pwrite(struct proc *, struct pwrite_args *, user_ssize_t *);
int hook_nfssvc(struct proc *, struct nfssvc_args *, int *);
int hook_statfs(struct proc *, struct statfs_args *, int *);
int hook_fstatfs(struct proc *, struct fstatfs_args *, int *);
int hook_unmount(struct proc *, struct unmount_args *, int *);
int hook_getfh(struct proc *, struct getfh_args *, int *);
int hook_quotactl(struct proc *, struct quotactl_args *, int *);
int hook_mount(struct proc *, struct mount_args *, int *);
int hook_csops(struct proc *, struct csops_args *, int *);
int hook_waitid(struct proc *, struct waitid_args *, int *);
int hook_kdebug_trace(struct proc *, struct kdebug_trace_args *, int *);
int hook_setgid(struct proc *, struct setgid_args *, int *);
int hook_setegid(struct proc *, struct setegid_args *, int *);
int hook_seteuid(struct proc *, struct seteuid_args *, int *);
int hook_sigreturn(struct proc *, struct sigreturn_args *, int *);
int hook_chud(struct proc *, struct chud_args *, int *);
int hook_fdatasync(struct proc *, struct fdatasync_args *, int *);
int hook_stat(struct proc *, struct stat_args *, int *);
int hook_fstat(struct proc *, struct fstat_args *, int *);
int hook_lstat(struct proc *, struct lstat_args *, int *);
int hook_pathconf(struct proc *, struct pathconf_args *, int *);
int hook_fpathconf(struct proc *, struct fpathconf_args *, int *);
int hook_getrlimit(struct proc *, struct getrlimit_args *, int *);
int hook_setrlimit(struct proc *, struct setrlimit_args *, int *);
int hook_getdirentries(struct proc *, struct getdirentries_args *, int *);
int hook_mmap(struct proc *, struct mmap_args *, user_addr_t *);
int hook_lseek(struct proc *, struct lseek_args *, off_t *);
int hook_truncate(struct proc *, struct truncate_args *, int *);
int hook_ftruncate(struct proc *, struct ftruncate_args *, int *);
int hook___sysctl(struct proc *, struct __sysctl_args *, int *);
int hook_mlock(struct proc *, struct mlock_args *, int *);
int hook_munlock(struct proc *, struct munlock_args *, int *);
int hook_undelete(struct proc *, struct undelete_args *, int *);
int hook_getattrlist(struct proc *, struct getattrlist_args *, int *);
int hook_setattrlist(struct proc *, struct setattrlist_args *, int *);
int hook_getdirentriesattr(struct proc *, struct getdirentriesattr_args *, int *);
int hook_exchangedata(struct proc *, struct exchangedata_args *, int *);
int hook_searchfs(struct proc *, struct searchfs_args *, int *);
int hook_delete(struct proc *, struct delete_args *, int *);
int hook_copyfile(struct proc *, struct copyfile_args *, int *);
int hook_fgetattrlist(struct proc *, struct fgetattrlist_args *, int *);
int hook_fsetattrlist(struct proc *, struct fsetattrlist_args *, int *);
int hook_poll(struct proc *, struct poll_args *, int *);
int hook_watchevent(struct proc *, struct watchevent_args *, int *);
int hook_waitevent(struct proc *, struct waitevent_args *, int *);
int hook_modwatch(struct proc *, struct modwatch_args *, int *);
int hook_getxattr(struct proc *, struct getxattr_args *, user_ssize_t *);
int hook_fgetxattr(struct proc *, struct fgetxattr_args *, user_ssize_t *);
int hook_setxattr(struct proc *, struct setxattr_args *, int *);
int hook_fsetxattr(struct proc *, struct fsetxattr_args *, int *);
int hook_removexattr(struct proc *, struct removexattr_args *, int *);
int hook_fremovexattr(struct proc *, struct fremovexattr_args *, int *);
int hook_listxattr(struct proc *, struct listxattr_args *, user_ssize_t *);
int hook_flistxattr(struct proc *, struct flistxattr_args *, user_ssize_t *);
int hook_fsctl(struct proc *, struct fsctl_args *, int *);
int hook_initgroups(struct proc *, struct initgroups_args *, int *);
int hook_posix_spawn(struct proc *, struct posix_spawn_args *, int *);
int hook_ffsctl(struct proc *, struct ffsctl_args *, int *);
int hook_nfsclnt(struct proc *, struct nfsclnt_args *, int *);
int hook_fhopen(struct proc *, struct fhopen_args *, int *);
int hook_minherit(struct proc *, struct minherit_args *, int *);
int hook_semsys(struct proc *, struct semsys_args *, int *);
int hook_msgsys(struct proc *, struct msgsys_args *, int *);
int hook_shmsys(struct proc *, struct shmsys_args *, int *);
int hook_semctl(struct proc *, struct semctl_args *, int *);
int hook_semget(struct proc *, struct semget_args *, int *);
int hook_semop(struct proc *, struct semop_args *, int *);
int hook_msgctl(struct proc *, struct msgctl_args *, int *);
int hook_msgget(struct proc *, struct msgget_args *, int *);
int hook_msgsnd(struct proc *, struct msgsnd_args *, int *);
int hook_msgrcv(struct proc *, struct msgrcv_args *, user_ssize_t *);
int hook_shmat(struct proc *, struct shmat_args *, user_addr_t *);
int hook_shmctl(struct proc *, struct shmctl_args *, int *);
int hook_shmdt(struct proc *, struct shmdt_args *, int *);
int hook_shmget(struct proc *, struct shmget_args *, int *);
int hook_shm_open(struct proc *, struct shm_open_args *, int *);
int hook_shm_unlink(struct proc *, struct shm_unlink_args *, int *);
int hook_sem_open(struct proc *, struct sem_open_args *, user_addr_t *);
int hook_sem_close(struct proc *, struct sem_close_args *, int *);
int hook_sem_unlink(struct proc *, struct sem_unlink_args *, int *);
int hook_sem_wait(struct proc *, struct sem_wait_args *, int *);
int hook_sem_trywait(struct proc *, struct sem_trywait_args *, int *);
int hook_sem_post(struct proc *, struct sem_post_args *, int *);
int hook_sysctlbyname(struct proc *, struct sysctlbyname_args *, int *);
int hook_sem_getvalue(struct proc *, struct sem_getvalue_args *, int *);
int hook_sem_init(struct proc *, struct sem_init_args *, int *);
int hook_sem_destroy(struct proc *, struct sem_destroy_args *, int *);
int hook_open_extended(struct proc *, struct open_extended_args *, int *);
int hook_umask_extended(struct proc *, struct umask_extended_args *, int *);
int hook_stat_extended(struct proc *, struct stat_extended_args *, int *);
int hook_lstat_extended(struct proc *, struct lstat_extended_args *, int *);
int hook_fstat_extended(struct proc *, struct fstat_extended_args *, int *);
int hook_chmod_extended(struct proc *, struct chmod_extended_args *, int *);
int hook_fchmod_extended(struct proc *, struct fchmod_extended_args *, int *);
int hook_access_extended(struct proc *, struct access_extended_args *, int *);
int hook_settid(struct proc *, struct settid_args *, int *);
int hook_gettid(struct proc *, struct gettid_args *, int *);
int hook_setsgroups(struct proc *, struct setsgroups_args *, int *);
int hook_getsgroups(struct proc *, struct getsgroups_args *, int *);
int hook_setwgroups(struct proc *, struct setwgroups_args *, int *);
int hook_getwgroups(struct proc *, struct getwgroups_args *, int *);
int hook_mkfifo_extended(struct proc *, struct mkfifo_extended_args *, int *);
int hook_mkdir_extended(struct proc *, struct mkdir_extended_args *, int *);
int hook_identitysvc(struct proc *, struct identitysvc_args *, int *);
int hook_shared_region_check_np(struct proc *, struct shared_region_check_np_args *, int *);
int hook_vm_pressure_monitor(struct proc *, struct vm_pressure_monitor_args *, int *);
int hook_psynch_rw_longrdlock(struct proc *, struct psynch_rw_longrdlock_args *, uint32_t *);
int hook_psynch_rw_yieldwrlock(struct proc *, struct psynch_rw_yieldwrlock_args *, uint32_t *);
int hook_psynch_rw_downgrade(struct proc *, struct psynch_rw_downgrade_args *, int *);
int hook_psynch_rw_upgrade(struct proc *, struct psynch_rw_upgrade_args *, uint32_t *);
int hook_psynch_mutexwait(struct proc *, struct psynch_mutexwait_args *, uint32_t *);
int hook_psynch_mutexdrop(struct proc *, struct psynch_mutexdrop_args *, uint32_t *);
int hook_psynch_cvbroad(struct proc *, struct psynch_cvbroad_args *, uint32_t *);
int hook_psynch_cvsignal(struct proc *, struct psynch_cvsignal_args *, uint32_t *);
int hook_psynch_cvwait(struct proc *, struct psynch_cvwait_args *, uint32_t *);
int hook_psynch_rw_rdlock(struct proc *, struct psynch_rw_rdlock_args *, uint32_t *);
int hook_psynch_rw_wrlock(struct proc *, struct psynch_rw_wrlock_args *, uint32_t *);
int hook_psynch_rw_unlock(struct proc *, struct psynch_rw_unlock_args *, uint32_t *);
int hook_psynch_rw_unlock2(struct proc *, struct psynch_rw_unlock2_args *, uint32_t *);
int hook_getsid(struct proc *, struct getsid_args *, int *);
int hook_settid_with_pid(struct proc *, struct settid_with_pid_args *, int *);
int hook_psynch_cvclrprepost(struct proc *, struct psynch_cvclrprepost_args *, int *);
int hook_aio_fsync(struct proc *, struct aio_fsync_args *, int *);
int hook_aio_return(struct proc *, struct aio_return_args *, user_ssize_t *);
int hook_aio_suspend(struct proc *, struct aio_suspend_args *, int *);
int hook_aio_cancel(struct proc *, struct aio_cancel_args *, int *);
int hook_aio_error(struct proc *, struct aio_error_args *, int *);
int hook_aio_read(struct proc *, struct aio_read_args *, int *);
int hook_aio_write(struct proc *, struct aio_write_args *, int *);
int hook_lio_listio(struct proc *, struct lio_listio_args *, int *);
int hook_iopolicysys(struct proc *, struct iopolicysys_args *, int *);
int hook_process_policy(struct proc *, struct process_policy_args *, int *);
int hook_mlockall(struct proc *, struct mlockall_args *, int *);
int hook_munlockall(struct proc *, struct munlockall_args *, int *);
int hook_issetugid(struct proc *, struct issetugid_args *, int *);
int hook___pthread_kill(struct proc *, struct __pthread_kill_args *, int *);
int hook___pthread_sigmask(struct proc *, struct __pthread_sigmask_args *, int *);
int hook___sigwait(struct proc *, struct __sigwait_args *, int *);
int hook___disable_threadsignal(struct proc *, struct __disable_threadsignal_args *, int *);
int hook___pthread_markcancel(struct proc *, struct __pthread_markcancel_args *, int *);
int hook___pthread_canceled(struct proc *, struct __pthread_canceled_args *, int *);
int hook___semwait_signal(struct proc *, struct __semwait_signal_args *, int *);
int hook_proc_info(struct proc *, struct proc_info_args *, int *);
int hook_sendfile(struct proc *, struct sendfile_args *, int *);
int hook_stat64(struct proc *, struct stat64_args *, int *);
int hook_fstat64(struct proc *, struct fstat64_args *, int *);
int hook_lstat64(struct proc *, struct lstat64_args *, int *);
int hook_stat64_extended(struct proc *, struct stat64_extended_args *, int *);
int hook_lstat64_extended(struct proc *, struct lstat64_extended_args *, int *);
int hook_fstat64_extended(struct proc *, struct fstat64_extended_args *, int *);
int hook_getdirentries64(struct proc *, struct getdirentries64_args *, user_ssize_t *);
int hook_statfs64(struct proc *, struct statfs64_args *, int *);
int hook_fstatfs64(struct proc *, struct fstatfs64_args *, int *);
int hook_getfsstat64(struct proc *, struct getfsstat64_args *, int *);
int hook___pthread_chdir(struct proc *, struct __pthread_chdir_args *, int *);
int hook___pthread_fchdir(struct proc *, struct __pthread_fchdir_args *, int *);
int hook_audit(struct proc *, struct audit_args *, int *);
int hook_auditon(struct proc *, struct auditon_args *, int *);
int hook_getauid(struct proc *, struct getauid_args *, int *);
int hook_setauid(struct proc *, struct setauid_args *, int *);
//int hook_getaudit(struct proc *, struct getaudit_args *, int *);
//int hook_setaudit(struct proc *, struct setaudit_args *, int *);
int hook_getaudit_addr(struct proc *, struct getaudit_addr_args *, int *);
int hook_setaudit_addr(struct proc *, struct setaudit_addr_args *, int *);
int hook_auditctl(struct proc *, struct auditctl_args *, int *);
int hook_bsdthread_create(struct proc *, struct bsdthread_create_args *, user_addr_t *);
int hook_bsdthread_terminate(struct proc *, struct bsdthread_terminate_args *, int *);
int hook_kqueue(struct proc *, struct kqueue_args *, int *);
int hook_kevent(struct proc *, struct kevent_args *, int *);
int hook_lchown(struct proc *, struct lchown_args *, int *);
int hook_stack_snapshot(struct proc *, struct stack_snapshot_args *, int *);
int hook_bsdthread_register(struct proc *, struct bsdthread_register_args *, int *);
int hook_workq_open(struct proc *, struct workq_open_args *, int *);
int hook_workq_kernreturn(struct proc *, struct workq_kernreturn_args *, int *);
int hook_kevent64(struct proc *, struct kevent64_args *, int *);
int hook___old_semwait_signal(struct proc *, struct __old_semwait_signal_args *, int *);
int hook___old_semwait_signal_nocancel(struct proc *, struct __old_semwait_signal_nocancel_args *, int *);
int hook_thread_selfid(struct proc *, struct thread_selfid_args *, uint64_t *);
int hook___mac_execve(struct proc *, struct __mac_execve_args *, int *);
int hook___mac_syscall(struct proc *, struct __mac_syscall_args *, int *);
int hook___mac_get_file(struct proc *, struct __mac_get_file_args *, int *);
int hook___mac_set_file(struct proc *, struct __mac_set_file_args *, int *);
int hook___mac_get_link(struct proc *, struct __mac_get_link_args *, int *);
int hook___mac_set_link(struct proc *, struct __mac_set_link_args *, int *);
int hook___mac_get_proc(struct proc *, struct __mac_get_proc_args *, int *);
int hook___mac_set_proc(struct proc *, struct __mac_set_proc_args *, int *);
int hook___mac_get_fd(struct proc *, struct __mac_get_fd_args *, int *);
int hook___mac_set_fd(struct proc *, struct __mac_set_fd_args *, int *);
int hook___mac_get_pid(struct proc *, struct __mac_get_pid_args *, int *);
int hook___mac_get_lcid(struct proc *, struct __mac_get_lcid_args *, int *);
int hook___mac_get_lctx(struct proc *, struct __mac_get_lctx_args *, int *);
int hook___mac_set_lctx(struct proc *, struct __mac_set_lctx_args *, int *);
int hook_pselect(struct proc *, struct pselect_args *, int *);
int hook_pselect_nocancel(struct proc *, struct pselect_nocancel_args *, int *);
int hook_read_nocancel(struct proc *, struct read_nocancel_args *, user_ssize_t *);
int hook_write_nocancel(struct proc *, struct write_nocancel_args *, user_ssize_t *);
int hook_open_nocancel(struct proc *, struct open_nocancel_args *, int *);
int hook_close_nocancel(struct proc *, struct close_nocancel_args *, int *);
int hook_wait4_nocancel(struct proc *, struct wait4_nocancel_args *, int *);
int hook_recvmsg_nocancel(struct proc *, struct recvmsg_nocancel_args *, int *);
int hook_sendmsg_nocancel(struct proc *, struct sendmsg_nocancel_args *, int *);
int hook_recvfrom_nocancel(struct proc *, struct recvfrom_nocancel_args *, int *);
int hook_accept_nocancel(struct proc *, struct accept_nocancel_args *, int *);
int hook_msync_nocancel(struct proc *, struct msync_nocancel_args *, int *);
int hook_fcntl_nocancel(struct proc *, struct fcntl_nocancel_args *, int *);
int hook_select_nocancel(struct proc *, struct select_nocancel_args *, int *);
int hook_fsync_nocancel(struct proc *, struct fsync_nocancel_args *, int *);
int hook_connect_nocancel(struct proc *, struct connect_nocancel_args *, int *);
int hook_sigsuspend_nocancel(struct proc *, struct sigsuspend_nocancel_args *, int *);
int hook_readv_nocancel(struct proc *, struct readv_nocancel_args *, user_ssize_t *);
int hook_writev_nocancel(struct proc *, struct writev_nocancel_args *, user_ssize_t *);
int hook_sendto_nocancel(struct proc *, struct sendto_nocancel_args *, int *);
int hook_pread_nocancel(struct proc *, struct pread_nocancel_args *, user_ssize_t *);
int hook_pwrite_nocancel(struct proc *, struct pwrite_nocancel_args *, user_ssize_t *);
int hook_waitid_nocancel(struct proc *, struct waitid_nocancel_args *, int *);
int hook_poll_nocancel(struct proc *, struct poll_nocancel_args *, int *);
int hook_msgsnd_nocancel(struct proc *, struct msgsnd_nocancel_args *, int *);
int hook_msgrcv_nocancel(struct proc *, struct msgrcv_nocancel_args *, user_ssize_t *);
int hook_sem_wait_nocancel(struct proc *, struct sem_wait_nocancel_args *, int *);
int hook_aio_suspend_nocancel(struct proc *, struct aio_suspend_nocancel_args *, int *);
int hook___sigwait_nocancel(struct proc *, struct __sigwait_nocancel_args *, int *);
int hook___semwait_signal_nocancel(struct proc *, struct __semwait_signal_nocancel_args *, int *);
int hook___mac_mount(struct proc *, struct __mac_mount_args *, int *);
int hook___mac_get_mount(struct proc *, struct __mac_get_mount_args *, int *);
int hook___mac_getfsstat(struct proc *, struct __mac_getfsstat_args *, int *);
int hook_fsgetpath(struct proc *, struct fsgetpath_args *, user_ssize_t *);
int hook_audit_session_self(struct proc *, struct audit_session_self_args *, mach_port_name_t *);
int hook_audit_session_join(struct proc *, struct audit_session_join_args *, int *);
int hook_fileport_makeport(struct proc *, struct fileport_makeport_args *, int *);
int hook_fileport_makefd(struct proc *, struct fileport_makefd_args *, int *);
int hook_audit_session_port(struct proc *, struct audit_session_port_args *, int *);
int hook_pid_suspend(struct proc *, struct pid_suspend_args *, int *);
int hook_pid_resume(struct proc *, struct pid_resume_args *, int *);
int hook_shared_region_map_and_slide_np(struct proc *, struct shared_region_map_and_slide_np_args *, int *);
int hook_kas_info(struct proc *, struct kas_info_args *, int *);
int hook_ioctl(struct proc *, struct ioctl_args *, int *);

int hook_guarded_open_np(struct proc *, struct guarded_open_np_args *, int *);


/* UPDATE MacOS 10.12.5**/

int hook_connectx(struct proc *, struct connectx_args *, int *);
int hook_disconnectx(struct proc *, struct disconnectx_args *, int *);
int hook_peeloff(struct proc *, struct peeloff_args *, int *);
int hook_socket_delegate(struct proc *, struct socket_delegate_args *, int *);
int hook_telemetry(struct proc *, struct telemetry_args *, int *);
int hook_proc_uuid_policy(struct proc *, struct proc_uuid_policy_args *, int *);
int hook_memorystatus_get_level(struct proc *, struct memorystatus_get_level_args *, int *);
int hook_system_override(struct proc *, struct system_override_args *, int *);
int hook_vfs_purge(struct proc *, struct vfs_purge_args *, int *);
int hook_sfi_ctl(struct proc *, struct sfi_ctl_args *, int *);
int hook_sfi_pidctl(struct proc *, struct sfi_pidctl_args *, int *);
int hook_coalition(struct proc *, struct coalition_args *, int *);
int hook_coalition_info(struct proc *, struct coalition_info_args *, int *);
int hook_necp_match_policy(struct proc *, struct necp_match_policy_args *, int *);
int hook_getattrlistbulk(struct proc *, struct getattrlistbulk_args *, int *);
int hook_clonefileat(struct proc *, struct clonefileat_args *, int *);
int hook_openat(struct proc *, struct openat_args *, int *);
int hook_openat_nocancel(struct proc *, struct openat_nocancel_args *, int *);
int hook_renameat(struct proc *, struct renameat_args *, int *);
int hook_faccessat(struct proc *, struct faccessat_args *, int *);
int hook_fchmodat(struct proc *, struct fchmodat_args *, int *);
int hook_fchownat(struct proc *, struct fchownat_args *, int *);
int hook_fstatat(struct proc *, struct fstatat_args *, int *);
int hook_fstatat64(struct proc *, struct fstatat64_args *, int *);
int hook_linkat(struct proc *, struct linkat_args *, int *);
int hook_unlinkat(struct proc *, struct unlinkat_args *, int *);
int hook_readlinkat(struct proc *, struct readlinkat_args *, int *);
int hook_symlinkat(struct proc *, struct symlinkat_args *, int *);
int hook_mkdirat(struct proc *, struct mkdirat_args *, int *);
int hook_getattrlistat(struct proc *, struct getattrlistat_args *, int *);
int hook_proc_trace_log(struct proc *, struct proc_trace_log_args *, int *);
int hook_bsdthread_ctl(struct proc *, struct bsdthread_ctl_args *, int *);
int hook_openbyid_np(struct proc *, struct openbyid_np_args *, int *);
int hook_recvmsg_x(struct proc *, struct recvmsg_x_args *, int *);
int hook_sendmsg_x(struct proc *, struct sendmsg_x_args *, int *);
int hook_thread_selfusage(struct proc *, struct thread_selfusage_args *, int *);
int hook_csrctl(struct proc *, struct csrctl_args *, int *);
int hook_guarded_open_dprotected_np(struct proc *, struct guarded_open_dprotected_np_args *, int *);
int hook_guarded_write_np(struct proc *, struct guarded_write_np_args *, int *);
int hook_guarded_pwrite_np(struct proc *, struct guarded_pwrite_np_args *, int *);
int hook_guarded_writev_np(struct proc *, struct guarded_writev_np_args *, int *);
int hook_renameatx_np(struct proc *, struct renameatx_np_args *, int *);
int hook_mremap_encrypted(struct proc *, struct mremap_encrypted_args *, int *);
int hook_netagent_trigger(struct proc *, struct netagent_trigger_args *, int *);
int hook_stack_snapshot_with_config(struct proc *, struct stack_snapshot_with_config_args *, int *);
int hook_microstackshot(struct proc *, struct microstackshot_args *, int *);
int hook_grab_pgo_data(struct proc *, struct grab_pgo_data_args *, int *);
int hook_persona(struct proc *, struct persona_args *, int *);
int hook_work_interval_ctl(struct proc *, struct work_interval_ctl_args *, int *);
int hook_getentropy(struct proc *, struct getentropy_args *, int *);
int hook_necp_open(struct proc *, struct necp_open_args *, int *);
int hook_necp_client_action(struct proc *, struct necp_client_action_args *, int *);
//int hook___nexus_open(struct proc *, struct __nexus_open_args *, int *);
//int hook___nexus_register(struct proc *, struct __nexus_register_args *, int *);
//int hook___nexus_deregister(struct proc *, struct __nexus_deregister_args *, int *);
//int hook___nexus_create(struct proc *, struct __nexus_create_args *, int *);
//int hook___nexus_destroy(struct proc *, struct __nexus_destroy_args *, int *);
//int hook___nexus_get_opt(struct proc *, struct __nexus_get_opt_args *, int *);
//int hook___nexus_set_opt(struct proc *, struct __nexus_set_opt_args *, int *);
//int hook___channel_open(struct proc *, struct __channel_open_args *, int *);
//int hook___channel_get_info(struct proc *, struct __channel_get_info_args *, int *);
//int hook___channel_sync(struct proc *, struct __channel_sync_args *, int *);
//int hook___channel_get_opt(struct proc *, struct __channel_get_opt_args *, int *);
//int hook___channel_set_opt(struct proc *, struct __channel_set_opt_args *, int *);
int hook_ulock_wait(struct proc *, struct ulock_wait_args *, int *);
int hook_ulock_wake(struct proc *, struct ulock_wake_args *, int *);
int hook_fclonefileat(struct proc *, struct fclonefileat_args *, int *);
int hook_fs_snapshot(struct proc *, struct fs_snapshot_args *, int *);
int hook_terminate_with_payload(struct proc *, struct terminate_with_payload_args *, int *);
int hook_abort_with_payload(struct proc *, struct abort_with_payload_args *, int *);
#endif /* hookehook_h */
