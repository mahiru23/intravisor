#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/snapshot.h>
#include <sys/sysproto.h>
#include <sys/mutex.h> 
#include <sys/sx.h>
#include <sys/sched.h>
#include <machine/pcb.h>
#include <machine/frame.h>


int sys_get_thread_snapshot(struct thread *td, struct get_thread_snapshot_args *uap)
{
    struct proc *p;
    struct thread *t;
    struct thread_snapshot ctx;
    int error;

    // find proc
    p = pfind(uap->pid);
    if (p == NULL)
        return ESRCH;

    // find thread
    t = tdfind(uap->threadid, uap->pid);
    if (t == NULL) {
        PROC_UNLOCK(p);
        return ESRCH;
    }

    thread_lock(t);

    memcpy(&(ctx.frame), t->td_frame, sizeof(struct trapframe)); // context
    // memory ...?

    thread_unlock(t);

    // copyout to userspace
    error = copyout(&ctx, uap->ctx, sizeof(ctx));
    PROC_UNLOCK(p);

    return (error);
}