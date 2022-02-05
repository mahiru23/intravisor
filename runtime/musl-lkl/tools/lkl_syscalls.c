#include <lkl.h>
#include <lkl_host.h>
#include <stdio.h>

#define str(s) #s
#define EXPORT_LKL_SYSCALL(name) \
	printf("__LKL_SYSCALL(" str(name) ")\n");

#define EXPORT_HOST_SYSCALL(name) \
	printf("#define __lkl__NR_" str(name) " __lkl__NR_syscalls+%d\n", __COUNTER__); \
	printf("__LKL_SYSCALL(" str(name) ")\n");

int main() {
	printf("// Generated using tools/lkl_syscalls.c , changes will be overwritten\n\n");
//	printf("#ifndef __LKL_SYSCALL\n");
//	printf("#define __LKL_SYSCALL(name) \n");
//	printf("#endif\n\n");
	EXPORT_LKL_SYSCALL(accept)
	EXPORT_LKL_SYSCALL(accept4)
	EXPORT_LKL_SYSCALL(acct)
	EXPORT_LKL_SYSCALL(add_key)
	EXPORT_LKL_SYSCALL(adjtimex)
	EXPORT_LKL_SYSCALL(bind)
	EXPORT_LKL_SYSCALL(bpf)
	EXPORT_LKL_SYSCALL(brk)
	EXPORT_LKL_SYSCALL(capget)
	EXPORT_LKL_SYSCALL(capset)
	EXPORT_LKL_SYSCALL(chdir)
	EXPORT_LKL_SYSCALL(chroot)
	EXPORT_LKL_SYSCALL(clock_adjtime)
	EXPORT_LKL_SYSCALL(clock_getres)
	EXPORT_LKL_SYSCALL(clock_gettime)
	EXPORT_LKL_SYSCALL(clock_nanosleep)
	EXPORT_LKL_SYSCALL(clock_settime)
	EXPORT_LKL_SYSCALL(clone)
	EXPORT_LKL_SYSCALL(close)
	EXPORT_LKL_SYSCALL(connect)
	EXPORT_LKL_SYSCALL(copy_file_range)
	EXPORT_LKL_SYSCALL(delete_module)
	EXPORT_LKL_SYSCALL(dup)
	EXPORT_LKL_SYSCALL(dup3)
	EXPORT_LKL_SYSCALL(epoll_create1)
	EXPORT_LKL_SYSCALL(epoll_ctl)
	EXPORT_LKL_SYSCALL(epoll_pwait)
	EXPORT_LKL_SYSCALL(eventfd2)
	EXPORT_LKL_SYSCALL(execve)
	EXPORT_LKL_SYSCALL(execveat)
	EXPORT_LKL_SYSCALL(exit)
	EXPORT_LKL_SYSCALL(exit_group)
	EXPORT_LKL_SYSCALL(faccessat)
	EXPORT_LKL_SYSCALL(fadvise64)
	EXPORT_LKL_SYSCALL(fallocate)
	EXPORT_LKL_SYSCALL(fanotify_init)
	EXPORT_LKL_SYSCALL(fanotify_mark)
	EXPORT_LKL_SYSCALL(fchdir)
	EXPORT_LKL_SYSCALL(fchmod)
	EXPORT_LKL_SYSCALL(fchmodat)
	EXPORT_LKL_SYSCALL(fchown)
	EXPORT_LKL_SYSCALL(fchownat)
	EXPORT_LKL_SYSCALL(fcntl)
	EXPORT_LKL_SYSCALL(fdatasync)
	EXPORT_LKL_SYSCALL(fgetxattr)
	EXPORT_LKL_SYSCALL(finit_module)
	EXPORT_LKL_SYSCALL(flistxattr)
	EXPORT_LKL_SYSCALL(flock)
	EXPORT_LKL_SYSCALL(fremovexattr)
	EXPORT_LKL_SYSCALL(fsetxattr)
	EXPORT_LKL_SYSCALL(fstat)
	EXPORT_LKL_SYSCALL(fstatfs)
	EXPORT_LKL_SYSCALL(fsync)
	EXPORT_LKL_SYSCALL(ftruncate)
	EXPORT_LKL_SYSCALL(futex)
	EXPORT_LKL_SYSCALL(getcwd)
	EXPORT_LKL_SYSCALL(getdents64)
	EXPORT_LKL_SYSCALL(getegid)
	EXPORT_LKL_SYSCALL(geteuid)
	EXPORT_LKL_SYSCALL(getgid)
	EXPORT_LKL_SYSCALL(getgroups)
	EXPORT_LKL_SYSCALL(getitimer)
	EXPORT_LKL_SYSCALL(get_mempolicy)
	EXPORT_LKL_SYSCALL(getpeername)
	EXPORT_LKL_SYSCALL(getpgid)
	EXPORT_LKL_SYSCALL(getpid)
	EXPORT_LKL_SYSCALL(getppid)
	EXPORT_LKL_SYSCALL(getpriority)
	EXPORT_LKL_SYSCALL(getrandom)
	EXPORT_LKL_SYSCALL(getresgid)
	EXPORT_LKL_SYSCALL(getresuid)
	EXPORT_LKL_SYSCALL(getrlimit)
	EXPORT_LKL_SYSCALL(get_robust_list)
	EXPORT_LKL_SYSCALL(getrusage)
	EXPORT_LKL_SYSCALL(getsid)
	EXPORT_LKL_SYSCALL(getsockname)
	EXPORT_LKL_SYSCALL(getsockopt)
	EXPORT_LKL_SYSCALL(gettid)
	EXPORT_LKL_SYSCALL(gettimeofday)
	EXPORT_LKL_SYSCALL(getuid)
	EXPORT_LKL_SYSCALL(getxattr)
	EXPORT_LKL_SYSCALL(init_module)
	EXPORT_LKL_SYSCALL(inotify_add_watch)
	EXPORT_LKL_SYSCALL(inotify_init1)
	EXPORT_LKL_SYSCALL(inotify_rm_watch)
	EXPORT_LKL_SYSCALL(io_cancel)
	EXPORT_LKL_SYSCALL(ioctl)
	EXPORT_LKL_SYSCALL(io_destroy)
	EXPORT_LKL_SYSCALL(io_getevents)
	EXPORT_LKL_SYSCALL(ioprio_get)
	EXPORT_LKL_SYSCALL(ioprio_set)
	EXPORT_LKL_SYSCALL(io_setup)
	EXPORT_LKL_SYSCALL(io_submit)
	EXPORT_LKL_SYSCALL(kcmp)
	EXPORT_LKL_SYSCALL(keyctl)
	EXPORT_LKL_SYSCALL(kill)
	EXPORT_LKL_SYSCALL(lgetxattr)
	EXPORT_LKL_SYSCALL(linkat)
	EXPORT_LKL_SYSCALL(listen)
	EXPORT_LKL_SYSCALL(listxattr)
	EXPORT_LKL_SYSCALL(llistxattr)
	EXPORT_LKL_SYSCALL(lookup_dcookie)
	EXPORT_LKL_SYSCALL(lremovexattr)
	EXPORT_LKL_SYSCALL(lseek)
	EXPORT_LKL_SYSCALL(lsetxattr)
	EXPORT_LKL_SYSCALL(madvise)
	EXPORT_LKL_SYSCALL(mbind)
	EXPORT_LKL_SYSCALL(membarrier)
	EXPORT_LKL_SYSCALL(memfd_create)
	EXPORT_LKL_SYSCALL(migrate_pages)
	EXPORT_LKL_SYSCALL(mincore)
	EXPORT_LKL_SYSCALL(mkdirat)
	EXPORT_LKL_SYSCALL(mknodat)
	EXPORT_LKL_SYSCALL(mlock)
	EXPORT_LKL_SYSCALL(mlock2)
	EXPORT_LKL_SYSCALL(mlockall)
	EXPORT_LKL_SYSCALL(mmap)
	EXPORT_LKL_SYSCALL(mount)
	EXPORT_LKL_SYSCALL(move_pages)
	EXPORT_LKL_SYSCALL(mprotect)
	EXPORT_LKL_SYSCALL(mq_getsetattr)
	EXPORT_LKL_SYSCALL(mq_notify)
	EXPORT_LKL_SYSCALL(mq_open)
	EXPORT_LKL_SYSCALL(mq_timedreceive)
	EXPORT_LKL_SYSCALL(mq_timedsend)
	EXPORT_LKL_SYSCALL(mq_unlink)
	EXPORT_LKL_SYSCALL(mremap)
	EXPORT_LKL_SYSCALL(msgctl)
	EXPORT_LKL_SYSCALL(msgget)
	EXPORT_LKL_SYSCALL(msgrcv)
	EXPORT_LKL_SYSCALL(msgsnd)
	EXPORT_LKL_SYSCALL(msync)
	EXPORT_LKL_SYSCALL(munlock)
	EXPORT_LKL_SYSCALL(munlockall)
	EXPORT_LKL_SYSCALL(munmap)
	EXPORT_LKL_SYSCALL(nanosleep)
	EXPORT_LKL_SYSCALL(newfstatat)
	EXPORT_LKL_SYSCALL(nfsservctl)
	EXPORT_LKL_SYSCALL(openat)
	EXPORT_LKL_SYSCALL(perf_event_open)
	EXPORT_LKL_SYSCALL(personality)
	EXPORT_LKL_SYSCALL(pipe2)
	EXPORT_LKL_SYSCALL(pivot_root)
	EXPORT_LKL_SYSCALL(ppoll)
	EXPORT_LKL_SYSCALL(prctl)
	EXPORT_LKL_SYSCALL(pread64)
	EXPORT_LKL_SYSCALL(preadv)
	EXPORT_LKL_SYSCALL(preadv2)
	EXPORT_LKL_SYSCALL(prlimit64)
	EXPORT_LKL_SYSCALL(process_vm_readv)
	EXPORT_LKL_SYSCALL(process_vm_writev)
	EXPORT_LKL_SYSCALL(pselect6)
	EXPORT_LKL_SYSCALL(ptrace)
	EXPORT_LKL_SYSCALL(pwrite64)
	EXPORT_LKL_SYSCALL(pwritev)
	EXPORT_LKL_SYSCALL(pwritev2)
	EXPORT_LKL_SYSCALL(quotactl)
	EXPORT_LKL_SYSCALL(read)
	EXPORT_LKL_SYSCALL(readahead)
	EXPORT_LKL_SYSCALL(readlinkat)
	EXPORT_LKL_SYSCALL(readv)
	EXPORT_LKL_SYSCALL(reboot)
	EXPORT_LKL_SYSCALL(recvfrom)
	EXPORT_LKL_SYSCALL(recvmmsg)
	EXPORT_LKL_SYSCALL(recvmsg)
	EXPORT_LKL_SYSCALL(remap_file_pages)
	EXPORT_LKL_SYSCALL(removexattr)
	EXPORT_LKL_SYSCALL(renameat)
	EXPORT_LKL_SYSCALL(renameat2)
	EXPORT_LKL_SYSCALL(request_key)
	EXPORT_LKL_SYSCALL(restart_syscall)
	EXPORT_LKL_SYSCALL(rt_sigaction)
	EXPORT_LKL_SYSCALL(rt_sigpending)
	EXPORT_LKL_SYSCALL(rt_sigprocmask)
	EXPORT_LKL_SYSCALL(rt_sigqueueinfo)
	EXPORT_LKL_SYSCALL(rt_sigreturn)
	EXPORT_LKL_SYSCALL(rt_sigsuspend)
	EXPORT_LKL_SYSCALL(rt_sigtimedwait)
	EXPORT_LKL_SYSCALL(rt_tgsigqueueinfo)
	EXPORT_LKL_SYSCALL(sched_getaffinity)
	EXPORT_LKL_SYSCALL(sched_get_priority_max)
	EXPORT_LKL_SYSCALL(sched_get_priority_min)
	EXPORT_LKL_SYSCALL(sched_getscheduler)
	EXPORT_LKL_SYSCALL(sched_rr_get_interval)
	EXPORT_LKL_SYSCALL(sched_setaffinity)
	EXPORT_LKL_SYSCALL(sched_yield)
	EXPORT_LKL_SYSCALL(seccomp)
	EXPORT_LKL_SYSCALL(semctl)
	EXPORT_LKL_SYSCALL(semget)
	EXPORT_LKL_SYSCALL(semop)
	EXPORT_LKL_SYSCALL(semtimedop)
	EXPORT_LKL_SYSCALL(sendfile)
	EXPORT_LKL_SYSCALL(sendmmsg)
	EXPORT_LKL_SYSCALL(sendmsg)
	EXPORT_LKL_SYSCALL(sendto)
	EXPORT_LKL_SYSCALL(setdomainname)
	EXPORT_LKL_SYSCALL(setfsgid)
	EXPORT_LKL_SYSCALL(setfsuid)
	EXPORT_LKL_SYSCALL(setgid)
	EXPORT_LKL_SYSCALL(setgroups)
	EXPORT_LKL_SYSCALL(sethostname)
	EXPORT_LKL_SYSCALL(setitimer)
	EXPORT_LKL_SYSCALL(set_mempolicy)
	EXPORT_LKL_SYSCALL(setns)
	EXPORT_LKL_SYSCALL(setpgid)
	EXPORT_LKL_SYSCALL(setpriority)
	EXPORT_LKL_SYSCALL(setregid)
	EXPORT_LKL_SYSCALL(setresgid)
	EXPORT_LKL_SYSCALL(setresuid)
	EXPORT_LKL_SYSCALL(setreuid)
	EXPORT_LKL_SYSCALL(setrlimit)
	EXPORT_LKL_SYSCALL(set_robust_list)
	EXPORT_LKL_SYSCALL(setsid)
	EXPORT_LKL_SYSCALL(setsockopt)
	EXPORT_LKL_SYSCALL(set_tid_address)
	EXPORT_LKL_SYSCALL(settimeofday)
	EXPORT_LKL_SYSCALL(setuid)
	EXPORT_LKL_SYSCALL(setxattr)
	EXPORT_LKL_SYSCALL(shmat)
	EXPORT_LKL_SYSCALL(shmctl)
	EXPORT_LKL_SYSCALL(shmdt)
	EXPORT_LKL_SYSCALL(shmget)
	EXPORT_LKL_SYSCALL(shutdown)
	EXPORT_LKL_SYSCALL(sigaltstack)
	EXPORT_LKL_SYSCALL(signalfd4)
	EXPORT_LKL_SYSCALL(socket)
	EXPORT_LKL_SYSCALL(socketpair)
	EXPORT_LKL_SYSCALL(splice)
	EXPORT_LKL_SYSCALL(statfs)
	EXPORT_LKL_SYSCALL(statx)
	EXPORT_LKL_SYSCALL(swapoff)
	EXPORT_LKL_SYSCALL(swapon)
	EXPORT_LKL_SYSCALL(symlinkat)
	EXPORT_LKL_SYSCALL(sync)
	EXPORT_LKL_SYSCALL(sync_file_range)
	EXPORT_LKL_SYSCALL(syncfs)
	EXPORT_LKL_SYSCALL(syscalls)
	EXPORT_LKL_SYSCALL(sysinfo)
	EXPORT_LKL_SYSCALL(syslog)
	EXPORT_LKL_SYSCALL(tee)
	EXPORT_LKL_SYSCALL(tgkill)
	EXPORT_LKL_SYSCALL(timer_create)
	EXPORT_LKL_SYSCALL(timer_delete)
	EXPORT_LKL_SYSCALL(timerfd_create)
	EXPORT_LKL_SYSCALL(timerfd_gettime)
	EXPORT_LKL_SYSCALL(timerfd_settime)
	EXPORT_LKL_SYSCALL(timer_getoverrun)
	EXPORT_LKL_SYSCALL(timer_gettime)
	EXPORT_LKL_SYSCALL(timer_settime)
	EXPORT_LKL_SYSCALL(times)
	EXPORT_LKL_SYSCALL(tkill)
	EXPORT_LKL_SYSCALL(truncate)
	EXPORT_LKL_SYSCALL(umask)
	EXPORT_LKL_SYSCALL(umount)
	EXPORT_LKL_SYSCALL(umount2)
	EXPORT_LKL_SYSCALL(uname)
	EXPORT_LKL_SYSCALL(unlinkat)
	EXPORT_LKL_SYSCALL(unshare)
	EXPORT_LKL_SYSCALL(userfaultfd)
	EXPORT_LKL_SYSCALL(utimensat)
	EXPORT_LKL_SYSCALL(vhangup)
	EXPORT_LKL_SYSCALL(vmsplice)
	EXPORT_LKL_SYSCALL(wait4)
	EXPORT_LKL_SYSCALL(waitid)
	EXPORT_LKL_SYSCALL(write)
	EXPORT_LKL_SYSCALL(writev)

	EXPORT_HOST_SYSCALL(arch_prctl)
	EXPORT_HOST_SYSCALL(iopl)
	EXPORT_HOST_SYSCALL(ioperm)
	EXPORT_HOST_SYSCALL(getcpu)

	printf("#undef __LKL_SYSCALL\n");
	return 0;
}
