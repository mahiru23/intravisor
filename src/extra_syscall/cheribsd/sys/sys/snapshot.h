
#ifndef _SYS_SNAPSHOT_H_
#define _SYS_SNAPSHOT_H_

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <machine/pcb.h>
#include <machine/frame.h>

struct thread_snapshot {
    struct trapframe frame;
    void *__capability stack;
};

// int get_thread_snapshot(pid_t pid, pthread_t tid, int threadid, struct thread_snapshot *ctx);

void recover_snapshot(void *);

int	kern_get_thread_snapshot(struct thread *td, pid_t pid, int threadid, struct thread_snapshot *__capability ctx);
int get_thread_snapshot(pid_t pid, int threadid, struct thread_snapshot *__capability ctx);


int	kern_resume_from_snapshot(struct thread *td, pid_t pid, int threadid, struct thread_snapshot *__capability ctx);
int resume_from_snapshot(pid_t pid, int threadid, struct thread_snapshot *__capability ctx);

#endif /* !_SYS_SNAPSHOT_H_ */