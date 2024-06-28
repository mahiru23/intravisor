/*
 * System call argument map.
 *
 * DO NOT EDIT-- this file is automatically @generated.
 * $FreeBSD$
 */

#ifndef _SYSARGMAP_H_
#define	_SYSARGMAP_H_

static int sysargmask[] = {
	[SYS_exit] = (0x0),
	[SYS_fork] = (0x0),
	[SYS_read] = (0x0 | 0x2),
	[SYS_write] = (0x0 | 0x2),
	[SYS_open] = (0x0 | 0x1),
	[SYS_close] = (0x0),
	[SYS_wait4] = (0x0 | 0x2 | 0x8),
	[SYS_link] = (0x0 | 0x1 | 0x2),
	[SYS_unlink] = (0x0 | 0x1),
	[SYS_chdir] = (0x0 | 0x1),
	[SYS_fchdir] = (0x0),
	[SYS_chmod] = (0x0 | 0x1),
	[SYS_chown] = (0x0 | 0x1),
	[SYS_break] = (0x0 | 0x1),
	[SYS_getpid] = (0x0),
	[SYS_mount] = (0x0 | 0x1 | 0x2 | 0x8),
	[SYS_unmount] = (0x0 | 0x1),
	[SYS_setuid] = (0x0),
	[SYS_getuid] = (0x0),
	[SYS_geteuid] = (0x0),
	[SYS_ptrace] = (0x0 | 0x4),
	[SYS_recvmsg] = (0x0 | 0x2),
	[SYS_sendmsg] = (0x0 | 0x2),
	[SYS_recvfrom] = (0x0 | 0x2 | 0x10 | 0x20),
	[SYS_accept] = (0x0 | 0x2 | 0x4),
	[SYS_getpeername] = (0x0 | 0x2 | 0x4),
	[SYS_getsockname] = (0x0 | 0x2 | 0x4),
	[SYS_access] = (0x0 | 0x1),
	[SYS_chflags] = (0x0 | 0x1),
	[SYS_fchflags] = (0x0),
	[SYS_sync] = (0x0),
	[SYS_kill] = (0x0),
	[SYS_getppid] = (0x0),
	[SYS_dup] = (0x0),
	[SYS_getegid] = (0x0),
	[SYS_profil] = (0x0 | 0x1),
	[SYS_ktrace] = (0x0 | 0x1),
	[SYS_getgid] = (0x0),
	[SYS_getlogin] = (0x0 | 0x1),
	[SYS_setlogin] = (0x0 | 0x1),
	[SYS_acct] = (0x0 | 0x1),
	[SYS_sigaltstack] = (0x0 | 0x1 | 0x2),
	[SYS_ioctl] = (0x0 | 0x4),
	[SYS_reboot] = (0x0),
	[SYS_revoke] = (0x0 | 0x1),
	[SYS_symlink] = (0x0 | 0x1 | 0x2),
	[SYS_readlink] = (0x0 | 0x1 | 0x2),
	[SYS_execve] = (0x0 | 0x1 | 0x2 | 0x4),
	[SYS_umask] = (0x0),
	[SYS_chroot] = (0x0 | 0x1),
	[SYS_msync] = (0x0 | 0x1),
	[SYS_vfork] = (0x0),
	[SYS_sbrk] = (0x0),
	[SYS_sstk] = (0x0),
	[SYS_munmap] = (0x0 | 0x1),
	[SYS_mprotect] = (0x0 | 0x1),
	[SYS_madvise] = (0x0 | 0x1),
	[SYS_mincore] = (0x0 | 0x1 | 0x4),
	[SYS_getgroups] = (0x0 | 0x2),
	[SYS_setgroups] = (0x0 | 0x2),
	[SYS_getpgrp] = (0x0),
	[SYS_setpgid] = (0x0),
	[SYS_setitimer] = (0x0 | 0x2 | 0x4),
	[SYS_swapon] = (0x0 | 0x1),
	[SYS_getitimer] = (0x0 | 0x2),
	[SYS_getdtablesize] = (0x0),
	[SYS_dup2] = (0x0),
	[SYS_fcntl] = (0x0 | 0x4),
	[SYS_select] = (0x0 | 0x2 | 0x4 | 0x8 | 0x10),
	[SYS_fsync] = (0x0),
	[SYS_setpriority] = (0x0),
	[SYS_socket] = (0x0),
	[SYS_connect] = (0x0 | 0x2),
	[SYS_getpriority] = (0x0),
	[SYS_bind] = (0x0 | 0x2),
	[SYS_setsockopt] = (0x0 | 0x8),
	[SYS_listen] = (0x0),
	[SYS_gettimeofday] = (0x0 | 0x1 | 0x2),
	[SYS_getrusage] = (0x0 | 0x2),
	[SYS_getsockopt] = (0x0 | 0x8 | 0x10),
	[SYS_readv] = (0x0 | 0x2),
	[SYS_writev] = (0x0 | 0x2),
	[SYS_settimeofday] = (0x0 | 0x1 | 0x2),
	[SYS_fchown] = (0x0),
	[SYS_fchmod] = (0x0),
	[SYS_setreuid] = (0x0),
	[SYS_setregid] = (0x0),
	[SYS_rename] = (0x0 | 0x1 | 0x2),
	[SYS_flock] = (0x0),
	[SYS_mkfifo] = (0x0 | 0x1),
	[SYS_sendto] = (0x0 | 0x2 | 0x10),
	[SYS_shutdown] = (0x0),
	[SYS_socketpair] = (0x0 | 0x8),
	[SYS_mkdir] = (0x0 | 0x1),
	[SYS_rmdir] = (0x0 | 0x1),
	[SYS_utimes] = (0x0 | 0x1 | 0x2),
	[SYS_adjtime] = (0x0 | 0x1 | 0x2),
	[SYS_setsid] = (0x0),
	[SYS_quotactl] = (0x0 | 0x1 | 0x8),
	[SYS_nlm_syscall] = (0x0 | 0x8),
	[SYS_nfssvc] = (0x0 | 0x2),
	[SYS_lgetfh] = (0x0 | 0x1 | 0x2),
	[SYS_getfh] = (0x0 | 0x1 | 0x2),
	[SYS_sysarch] = (0x0 | 0x2),
	[SYS_rtprio] = (0x0 | 0x4),
	[SYS_semsys] = (0x0 | 0x2 | 0x4 | 0x8 | 0x10),
	[SYS_msgsys] = (0x0 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20),
	[SYS_shmsys] = (0x0 | 0x2 | 0x4 | 0x8),
	[SYS_setfib] = (0x0),
	[SYS_ntp_adjtime] = (0x0 | 0x1),
	[SYS_setgid] = (0x0),
	[SYS_setegid] = (0x0),
	[SYS_seteuid] = (0x0),
	[SYS_pathconf] = (0x0 | 0x1),
	[SYS_fpathconf] = (0x0),
	[SYS_getrlimit] = (0x0 | 0x2),
	[SYS_setrlimit] = (0x0 | 0x2),
	[SYS___sysctl] = (0x0 | 0x1 | 0x4 | 0x8 | 0x10),
	[SYS_mlock] = (0x0 | 0x1),
	[SYS_munlock] = (0x0 | 0x1),
	[SYS_undelete] = (0x0 | 0x1),
	[SYS_futimes] = (0x0 | 0x2),
	[SYS_getpgid] = (0x0),
	[SYS_poll] = (0x0 | 0x1),
	[SYS_semget] = (0x0),
	[SYS_semop] = (0x0 | 0x2),
	[SYS_msgget] = (0x0),
	[SYS_msgsnd] = (0x0 | 0x2),
	[SYS_msgrcv] = (0x0 | 0x2),
	[SYS_shmat] = (0x0 | 0x2),
	[SYS_shmdt] = (0x0 | 0x1),
	[SYS_shmget] = (0x0),
	[SYS_clock_gettime] = (0x0 | 0x2),
	[SYS_clock_settime] = (0x0 | 0x2),
	[SYS_clock_getres] = (0x0 | 0x2),
	[SYS_ktimer_create] = (0x0 | 0x2 | 0x4),
	[SYS_ktimer_delete] = (0x0),
	[SYS_ktimer_settime] = (0x0 | 0x4 | 0x8),
	[SYS_ktimer_gettime] = (0x0 | 0x2),
	[SYS_ktimer_getoverrun] = (0x0),
	[SYS_nanosleep] = (0x0 | 0x1 | 0x2),
	[SYS_ffclock_getcounter] = (0x0 | 0x1),
	[SYS_ffclock_setestimate] = (0x0 | 0x1),
	[SYS_ffclock_getestimate] = (0x0 | 0x1),
	[SYS_clock_nanosleep] = (0x0 | 0x4 | 0x8),
	[SYS_clock_getcpuclockid2] = (0x0 | 0x4),
	[SYS_ntp_gettime] = (0x0 | 0x1),
	[SYS_minherit] = (0x0 | 0x1),
	[SYS_rfork] = (0x0),
	[SYS_issetugid] = (0x0),
	[SYS_lchown] = (0x0 | 0x1),
	[SYS_aio_read] = (0x0 | 0x1),
	[SYS_aio_write] = (0x0 | 0x1),
	[SYS_lio_listio] = (0x0 | 0x2 | 0x8),
	[SYS_kbounce] = (0x0 | 0x1 | 0x2),
	[SYS_flag_captured] = (0x0 | 0x1),
	[SYS_lchmod] = (0x0 | 0x1),
	[SYS_lutimes] = (0x0 | 0x1 | 0x2),
	[SYS_preadv] = (0x0 | 0x2),
	[SYS_pwritev] = (0x0 | 0x2),
	[SYS_fhopen] = (0x0 | 0x1),
	[SYS_modnext] = (0x0),
	[SYS_modstat] = (0x0 | 0x2),
	[SYS_modfnext] = (0x0),
	[SYS_modfind] = (0x0 | 0x1),
	[SYS_kldload] = (0x0 | 0x1),
	[SYS_kldunload] = (0x0),
	[SYS_kldfind] = (0x0 | 0x1),
	[SYS_kldnext] = (0x0),
	[SYS_kldstat] = (0x0 | 0x2),
	[SYS_kldfirstmod] = (0x0),
	[SYS_getsid] = (0x0),
	[SYS_setresuid] = (0x0),
	[SYS_setresgid] = (0x0),
	[SYS_aio_return] = (0x0 | 0x1),
	[SYS_aio_suspend] = (0x0 | 0x1 | 0x4),
	[SYS_aio_cancel] = (0x0 | 0x2),
	[SYS_aio_error] = (0x0 | 0x1),
	[SYS_yield] = (0x0),
	[SYS_mlockall] = (0x0),
	[SYS_munlockall] = (0x0),
	[SYS___getcwd] = (0x0 | 0x1),
	[SYS_sched_setparam] = (0x0 | 0x2),
	[SYS_sched_getparam] = (0x0 | 0x2),
	[SYS_sched_setscheduler] = (0x0 | 0x4),
	[SYS_sched_getscheduler] = (0x0),
	[SYS_sched_yield] = (0x0),
	[SYS_sched_get_priority_max] = (0x0),
	[SYS_sched_get_priority_min] = (0x0),
	[SYS_sched_rr_get_interval] = (0x0 | 0x2),
	[SYS_utrace] = (0x0 | 0x1),
	[SYS_kldsym] = (0x0 | 0x4),
	[SYS_jail] = (0x0 | 0x1),
	[SYS_nnpfs_syscall] = (0x0 | 0x2 | 0x8),
	[SYS_sigprocmask] = (0x0 | 0x2 | 0x4),
	[SYS_sigsuspend] = (0x0 | 0x1),
	[SYS_sigpending] = (0x0 | 0x1),
	[SYS_sigtimedwait] = (0x0 | 0x1 | 0x2 | 0x4),
	[SYS_sigwaitinfo] = (0x0 | 0x1 | 0x2),
	[SYS___acl_get_file] = (0x0 | 0x1 | 0x4),
	[SYS___acl_set_file] = (0x0 | 0x1 | 0x4),
	[SYS___acl_get_fd] = (0x0 | 0x4),
	[SYS___acl_set_fd] = (0x0 | 0x4),
	[SYS___acl_delete_file] = (0x0 | 0x1),
	[SYS___acl_delete_fd] = (0x0),
	[SYS___acl_aclcheck_file] = (0x0 | 0x1 | 0x4),
	[SYS___acl_aclcheck_fd] = (0x0 | 0x4),
	[SYS_extattrctl] = (0x0 | 0x1 | 0x4 | 0x10),
	[SYS_extattr_set_file] = (0x0 | 0x1 | 0x4 | 0x8),
	[SYS_extattr_get_file] = (0x0 | 0x1 | 0x4 | 0x8),
	[SYS_extattr_delete_file] = (0x0 | 0x1 | 0x4),
	[SYS_aio_waitcomplete] = (0x0 | 0x1 | 0x2),
	[SYS_getresuid] = (0x0 | 0x1 | 0x2 | 0x4),
	[SYS_getresgid] = (0x0 | 0x1 | 0x2 | 0x4),
	[SYS_kqueue] = (0x0),
	[SYS_extattr_set_fd] = (0x0 | 0x4 | 0x8),
	[SYS_extattr_get_fd] = (0x0 | 0x4 | 0x8),
	[SYS_extattr_delete_fd] = (0x0 | 0x4),
	[SYS___setugid] = (0x0),
	[SYS_eaccess] = (0x0 | 0x1),
	[SYS_afs3_syscall] = (0x0),
	[SYS_nmount] = (0x0 | 0x1),
	[SYS___mac_get_proc] = (0x0 | 0x1),
	[SYS___mac_set_proc] = (0x0 | 0x1),
	[SYS___mac_get_fd] = (0x0 | 0x2),
	[SYS___mac_get_file] = (0x0 | 0x1 | 0x2),
	[SYS___mac_set_fd] = (0x0 | 0x2),
	[SYS___mac_set_file] = (0x0 | 0x1 | 0x2),
	[SYS_kenv] = (0x0 | 0x2 | 0x4),
	[SYS_lchflags] = (0x0 | 0x1),
	[SYS_uuidgen] = (0x0 | 0x1),
	[SYS_sendfile] = (0x0 | 0x10 | 0x20),
	[SYS_mac_syscall] = (0x0 | 0x1 | 0x4),
	[SYS_ksem_close] = (0x0),
	[SYS_ksem_post] = (0x0),
	[SYS_ksem_wait] = (0x0),
	[SYS_ksem_trywait] = (0x0),
	[SYS_ksem_init] = (0x0 | 0x1),
	[SYS_ksem_open] = (0x0 | 0x1 | 0x2),
	[SYS_ksem_unlink] = (0x0 | 0x1),
	[SYS_ksem_getvalue] = (0x0 | 0x2),
	[SYS_ksem_destroy] = (0x0),
	[SYS___mac_get_pid] = (0x0 | 0x2),
	[SYS___mac_get_link] = (0x0 | 0x1 | 0x2),
	[SYS___mac_set_link] = (0x0 | 0x1 | 0x2),
	[SYS_extattr_set_link] = (0x0 | 0x1 | 0x4 | 0x8),
	[SYS_extattr_get_link] = (0x0 | 0x1 | 0x4 | 0x8),
	[SYS_extattr_delete_link] = (0x0 | 0x1 | 0x4),
	[SYS___mac_execve] = (0x0 | 0x1 | 0x2 | 0x4 | 0x8),
	[SYS_sigaction] = (0x0 | 0x2 | 0x4),
	[SYS_sigreturn] = (0x0 | 0x1),
	[SYS_getcontext] = (0x0 | 0x1),
	[SYS_setcontext] = (0x0 | 0x1),
	[SYS_swapcontext] = (0x0 | 0x1 | 0x2),
	[SYS___acl_get_link] = (0x0 | 0x1 | 0x4),
	[SYS___acl_set_link] = (0x0 | 0x1 | 0x4),
	[SYS___acl_delete_link] = (0x0 | 0x1),
	[SYS___acl_aclcheck_link] = (0x0 | 0x1 | 0x4),
	[SYS_sigwait] = (0x0 | 0x1 | 0x2),
	[SYS_thr_create] = (0x0 | 0x1 | 0x2),
	[SYS_thr_exit] = (0x0 | 0x1),
	[SYS_thr_self] = (0x0 | 0x1),
	[SYS_thr_kill] = (0x0),
	[SYS_jail_attach] = (0x0),
	[SYS_extattr_list_fd] = (0x0 | 0x4),
	[SYS_extattr_list_file] = (0x0 | 0x1 | 0x4),
	[SYS_extattr_list_link] = (0x0 | 0x1 | 0x4),
	[SYS_ksem_timedwait] = (0x0 | 0x2),
	[SYS_thr_suspend] = (0x0 | 0x1),
	[SYS_thr_wake] = (0x0),
	[SYS_kldunloadf] = (0x0),
	[SYS_audit] = (0x0 | 0x1),
	[SYS_auditon] = (0x0 | 0x2),
	[SYS_getauid] = (0x0 | 0x1),
	[SYS_setauid] = (0x0 | 0x1),
	[SYS_getaudit] = (0x0 | 0x1),
	[SYS_setaudit] = (0x0 | 0x1),
	[SYS_getaudit_addr] = (0x0 | 0x1),
	[SYS_setaudit_addr] = (0x0 | 0x1),
	[SYS_auditctl] = (0x0 | 0x1),
	[SYS__umtx_op] = (0x0 | 0x1 | 0x8 | 0x10),
	[SYS_thr_new] = (0x0 | 0x1),
	[SYS_sigqueue] = (0x0 | 0x4),
	[SYS_kmq_open] = (0x0 | 0x1 | 0x8),
	[SYS_kmq_setattr] = (0x0 | 0x2 | 0x4),
	[SYS_kmq_timedreceive] = (0x0 | 0x2 | 0x8 | 0x10),
	[SYS_kmq_timedsend] = (0x0 | 0x2 | 0x10),
	[SYS_kmq_notify] = (0x0 | 0x2),
	[SYS_kmq_unlink] = (0x0 | 0x1),
	[SYS_abort2] = (0x0 | 0x1 | 0x4),
	[SYS_thr_set_name] = (0x0 | 0x2),
	[SYS_aio_fsync] = (0x0 | 0x2),
	[SYS_rtprio_thread] = (0x0 | 0x4),
	[SYS_sctp_peeloff] = (0x0),
	[SYS_sctp_generic_sendmsg] = (0x0 | 0x2 | 0x8 | 0x20),
	[SYS_sctp_generic_sendmsg_iov] = (0x0 | 0x2 | 0x8 | 0x20),
	[SYS_sctp_generic_recvmsg] = (0x0 | 0x2 | 0x8 | 0x10 | 0x20 | 0x40),
	[SYS_pread] = (0x0 | 0x2),
	[SYS_pwrite] = (0x0 | 0x2),
	[SYS_mmap] = (0x0 | 0x1),
	[SYS_lseek] = (0x0),
	[SYS_truncate] = (0x0 | 0x1),
	[SYS_ftruncate] = (0x0),
	[SYS_thr_kill2] = (0x0),
	[SYS_shm_unlink] = (0x0 | 0x1),
	[SYS_cpuset] = (0x0 | 0x1),
	[SYS_cpuset_setid] = (0x0),
	[SYS_cpuset_getid] = (0x0 | 0x8),
	[SYS_cpuset_getaffinity] = (0x0 | 0x10),
	[SYS_cpuset_setaffinity] = (0x0 | 0x10),
	[SYS_faccessat] = (0x0 | 0x2),
	[SYS_fchmodat] = (0x0 | 0x2),
	[SYS_fchownat] = (0x0 | 0x2),
	[SYS_fexecve] = (0x0 | 0x2 | 0x4),
	[SYS_futimesat] = (0x0 | 0x2 | 0x4),
	[SYS_linkat] = (0x0 | 0x2 | 0x8),
	[SYS_mkdirat] = (0x0 | 0x2),
	[SYS_mkfifoat] = (0x0 | 0x2),
	[SYS_openat] = (0x0 | 0x2),
	[SYS_readlinkat] = (0x0 | 0x2 | 0x4),
	[SYS_renameat] = (0x0 | 0x2 | 0x8),
	[SYS_symlinkat] = (0x0 | 0x1 | 0x4),
	[SYS_unlinkat] = (0x0 | 0x2),
	[SYS_posix_openpt] = (0x0),
	[SYS_gssd_syscall] = (0x0 | 0x1),
	[SYS_jail_get] = (0x0 | 0x1),
	[SYS_jail_set] = (0x0 | 0x1),
	[SYS_jail_remove] = (0x0),
	[SYS___semctl] = (0x0 | 0x8),
	[SYS_msgctl] = (0x0 | 0x4),
	[SYS_shmctl] = (0x0 | 0x4),
	[SYS_lpathconf] = (0x0 | 0x1),
	[SYS___cap_rights_get] = (0x0 | 0x4),
	[SYS_cap_enter] = (0x0),
	[SYS_cap_getmode] = (0x0 | 0x1),
	[SYS_pdfork] = (0x0 | 0x1),
	[SYS_pdkill] = (0x0),
	[SYS_pdgetpid] = (0x0 | 0x2),
	[SYS_pselect] = (0x0 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20),
	[SYS_getloginclass] = (0x0 | 0x1),
	[SYS_setloginclass] = (0x0 | 0x1),
	[SYS_rctl_get_racct] = (0x0 | 0x1 | 0x4),
	[SYS_rctl_get_rules] = (0x0 | 0x1 | 0x4),
	[SYS_rctl_get_limits] = (0x0 | 0x1 | 0x4),
	[SYS_rctl_add_rule] = (0x0 | 0x1 | 0x4),
	[SYS_rctl_remove_rule] = (0x0 | 0x1 | 0x4),
	[SYS_posix_fallocate] = (0x0),
	[SYS_posix_fadvise] = (0x0),
	[SYS_wait6] = (0x0 | 0x4 | 0x10 | 0x20),
	[SYS_cap_rights_limit] = (0x0 | 0x2),
	[SYS_cap_ioctls_limit] = (0x0 | 0x2),
	[SYS_cap_ioctls_get] = (0x0 | 0x2),
	[SYS_cap_fcntls_limit] = (0x0),
	[SYS_cap_fcntls_get] = (0x0 | 0x2),
	[SYS_bindat] = (0x0 | 0x4),
	[SYS_connectat] = (0x0 | 0x4),
	[SYS_chflagsat] = (0x0 | 0x2),
	[SYS_accept4] = (0x0 | 0x2 | 0x4),
	[SYS_pipe2] = (0x0 | 0x1),
	[SYS_aio_mlock] = (0x0 | 0x1),
	[SYS_procctl] = (0x0 | 0x8),
	[SYS_ppoll] = (0x0 | 0x1 | 0x4 | 0x8),
	[SYS_futimens] = (0x0 | 0x2),
	[SYS_utimensat] = (0x0 | 0x2 | 0x4),
	[SYS_fdatasync] = (0x0),
	[SYS_fstat] = (0x0 | 0x2),
	[SYS_fstatat] = (0x0 | 0x2 | 0x4),
	[SYS_fhstat] = (0x0 | 0x1 | 0x2),
	[SYS_getdirentries] = (0x0 | 0x2 | 0x8),
	[SYS_statfs] = (0x0 | 0x1 | 0x2),
	[SYS_fstatfs] = (0x0 | 0x2),
	[SYS_getfsstat] = (0x0 | 0x1),
	[SYS_fhstatfs] = (0x0 | 0x1 | 0x2),
	[SYS_mknodat] = (0x0 | 0x2),
	[SYS_kevent] = (0x0 | 0x2 | 0x8 | 0x20),
	[SYS_cpuset_getdomain] = (0x0 | 0x10 | 0x20),
	[SYS_cpuset_setdomain] = (0x0 | 0x10),
	[SYS_getrandom] = (0x0 | 0x1),
	[SYS_getfhat] = (0x0 | 0x2 | 0x4),
	[SYS_fhlink] = (0x0 | 0x1 | 0x2),
	[SYS_fhlinkat] = (0x0 | 0x1 | 0x4),
	[SYS_fhreadlink] = (0x0 | 0x1 | 0x2),
	[SYS_funlinkat] = (0x0 | 0x2),
	[SYS_copy_file_range] = (0x0 | 0x2 | 0x8),
	[SYS___sysctlbyname] = (0x0 | 0x1 | 0x4 | 0x8 | 0x10),
	[SYS_shm_open2] = (0x0 | 0x1 | 0x10),
	[SYS_shm_rename] = (0x0 | 0x1 | 0x2),
	[SYS_sigfastblock] = (0x0 | 0x2),
	[SYS___realpathat] = (0x0 | 0x2 | 0x4),
	[SYS_close_range] = (0x0),
	[SYS_rpctls_syscall] = (0x0 | 0x2),
	[SYS___specialfd] = (0x0 | 0x2),
	[SYS_aio_writev] = (0x0 | 0x1),
	[SYS_aio_readv] = (0x0 | 0x1),
	[SYS_fspacectl] = (0x0 | 0x4 | 0x10),
	[SYS_sched_getcpu] = (0x0),
	[SYS_swapoff] = (0x0 | 0x1),
	[SYS_get_thread_snapshot] = (0x0 | 0x1),
	[SYS_resume_from_snapshot] = (0x0 | 0x1),
	[SYS_msync_manual] = (0x0 | 0x1 | 0x4),
};

#endif /* !_SYSARGMAP_H_ */
