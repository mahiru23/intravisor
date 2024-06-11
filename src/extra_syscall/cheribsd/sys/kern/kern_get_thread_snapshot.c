#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/snapshot.h>
#include <sys/sysproto.h>
#include <sys/mutex.h> 
#include <sys/mman.h> 
#include <sys/fcntl.h>
#include <sys/sx.h>
#include <sys/sched.h>
#include <sys/syslog.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/stddef.h>
#include <sys/sysent.h>

#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/malloc.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <vm/vm_pager.h>

#include <cheri/cheric.h>
#include <machine/pcb.h>
#include <machine/frame.h>

#define	CHERI_CAP_PRINT_KERN(cap) do {					\
  log(LOG_WARNING, "tag %ju s %ju perms %08jx type %016jx\n",		\
      (uintmax_t)cheri_gettag(cap),				\
      (uintmax_t)cheri_getsealed(cap),				\
      (uintmax_t)cheri_getperm(cap),				\
      (uintmax_t)cheri_gettype(cap));				\
  log(LOG_WARNING, "\tbase %016jx length %016jx ofset %016jx\n",				\
      (uintmax_t)cheri_getbase(cap),				\
      (uintmax_t)cheri_getlen(cap),				\
      (uintmax_t)cheri_getoffset(cap));				\
} while (0)

int	kern_get_thread_snapshot(struct thread *td, pid_t pid_flag, int threadid, struct thread_snapshot *__capability ctx) {

    struct proc *p;
    struct thread *t;
    struct thread_snapshot ctx2;
    int error;

    p = td->td_proc;
    pid_t pid = p->p_pid;


    // find thread
    t = tdfind(threadid, pid);
    if (t == NULL) {
        //PROC_UNLOCK(p);
        log(LOG_WARNING, "tdfind error\n");
        return ESRCH;
    }

    log(LOG_WARNING, "Debug: thread is %p\n", t);

    PROC_UNLOCK(p);

    if(pid_flag == -1) //suspend
    {
        PROC_SLOCK(p);
        thread_lock(t);
        thread_suspend_one(t);
        thread_unlock(t);
        PROC_SUNLOCK(p);
        log(LOG_WARNING, "Debug: thread is suspend \n");
        return 0;
    }

    if(pid_flag == -2) //resume
    {
        PROC_LOCK(p);
        PROC_SLOCK(p);
        thread_unsuspend(p);
        PROC_SUNLOCK(p);
        PROC_UNLOCK(p);
        log(LOG_WARNING, "Debug: thread is resume \n");
        return 0;
    }

    /*if(pid_flag == -3) //suspend and lock thread
    {
        PROC_SLOCK(p);
        thread_lock(t);
        thread_suspend_one(t);
        PROC_SUNLOCK(p);
        log(LOG_WARNING, "Debug: thread is suspend and lock\n");
        return 0;
    }

    if(pid_flag == -4) //resume and unlock thread
    {
        PROC_LOCK(p);
        PROC_SLOCK(p);
        thread_unlock(t);
        thread_unsuspend(p);
        PROC_SUNLOCK(p);
        PROC_UNLOCK(p);
        log(LOG_WARNING, "Debug: thread is resume and unlock \n");
        return 0;
    }


    if(pid_flag == -5) 
    {
        PROC_LOCK(p);
        //thread_lock(t);

        memcpy(&(ctx2.frame), t->td_frame, sizeof(struct trapframe)); // context
        error = copyoutcap(&ctx2, ctx, sizeof(struct thread_snapshot)); // copyout to userspace
        log(LOG_WARNING, "Debug: error is %d\n", error);

        thread_unlock(t);
        PROC_UNLOCK(p);
    }*/

    if(pid_flag == -6) 
    {
        PROC_LOCK(p);
        thread_lock(t);

        memcpy(&(ctx2.frame), t->td_frame, sizeof(struct trapframe)); // context
        error = copyoutcap(&ctx2, ctx, sizeof(struct thread_snapshot)); // copyout to userspace
        log(LOG_WARNING, "Debug: error is %d\n", error);

        thread_unlock(t);
        PROC_UNLOCK(p);
    }



    return 0;
}

int sys_get_thread_snapshot(struct thread *td, struct get_thread_snapshot_args *uap)
{
    return (kern_get_thread_snapshot(td, uap->pid, uap->threadid, uap->ctx));
}



int	kern_resume_from_snapshot(struct thread *td, pid_t pid, int threadid, struct thread_snapshot *__capability ctx) {
    struct proc *p;
    struct thread *t;
    struct thread_snapshot ctx_in;

    p = td->td_proc;
    pid = p->p_pid;

    // find thread
    t = tdfind(threadid, pid);
    if (t == NULL) {
        //PROC_UNLOCK(p);
        log(LOG_WARNING, "tdfind error\n");
        return ESRCH;
    }

    log(LOG_WARNING, "tdfind ok\n");
    log(LOG_WARNING, "Debug: thread is %p\n", t);
    log(LOG_WARNING, "t->td_frame start\n");

    /*reg*/

    int error = copyincap(ctx, &ctx_in, sizeof(ctx_in));
    if (error) {
        return error;
    }

    t->td_frame->tf_ra = ctx_in.frame.tf_ra;
    t->td_frame->tf_sp = ctx_in.frame.tf_sp;
    t->td_frame->tf_gp = ctx_in.frame.tf_gp;
    t->td_frame->tf_tp = ctx_in.frame.tf_tp;
    t->td_frame->tf_t[0] = ctx_in.frame.tf_t[0];
    t->td_frame->tf_t[1] = ctx_in.frame.tf_t[1];
    t->td_frame->tf_t[2] = ctx_in.frame.tf_t[2];
    t->td_frame->tf_t[3] = ctx_in.frame.tf_t[3];
    t->td_frame->tf_t[4] = ctx_in.frame.tf_t[4];
    t->td_frame->tf_t[5] = ctx_in.frame.tf_t[5];
    t->td_frame->tf_t[6] = ctx_in.frame.tf_t[6];
    t->td_frame->tf_s[0] = ctx_in.frame.tf_s[0];
    t->td_frame->tf_s[1] = ctx_in.frame.tf_s[1];
    t->td_frame->tf_s[2] = ctx_in.frame.tf_s[2];
    t->td_frame->tf_s[3] = ctx_in.frame.tf_s[3];
    t->td_frame->tf_s[4] = ctx_in.frame.tf_s[4];
    t->td_frame->tf_s[5] = ctx_in.frame.tf_s[5];
    t->td_frame->tf_s[6] = ctx_in.frame.tf_s[6];
    t->td_frame->tf_s[7] = ctx_in.frame.tf_s[7];
    t->td_frame->tf_s[8] = ctx_in.frame.tf_s[8];
    t->td_frame->tf_s[9] = ctx_in.frame.tf_s[9];
    t->td_frame->tf_s[10] = ctx_in.frame.tf_s[10];
    t->td_frame->tf_s[11] = ctx_in.frame.tf_s[11];
    t->td_frame->tf_a[0] = ctx_in.frame.tf_a[0];
    t->td_frame->tf_a[1] = ctx_in.frame.tf_a[1];
    t->td_frame->tf_a[2] = ctx_in.frame.tf_a[2];
    t->td_frame->tf_a[3] = ctx_in.frame.tf_a[3];
    t->td_frame->tf_a[4] = ctx_in.frame.tf_a[4];
    t->td_frame->tf_a[5] = ctx_in.frame.tf_a[5];
    t->td_frame->tf_a[6] = ctx_in.frame.tf_a[6];
    t->td_frame->tf_a[7] = ctx_in.frame.tf_a[7];
    t->td_frame->tf_sepc = ctx_in.frame.tf_sepc;
    t->td_frame->tf_ddc = ctx_in.frame.tf_ddc;

    t->td_frame->tf_sstatus = ctx_in.frame.tf_sstatus;
    /*t->td_frame->tf_stval = ctx_in.frame.tf_stval;
    t->td_frame->tf_scause = ctx_in.frame.tf_scause;*/

    log(LOG_WARNING, "t->td_frame ok\n");
    log(LOG_WARNING, "over\n");
    PROC_UNLOCK(p);

    return 0;
}






int sys_resume_from_snapshot(struct thread *td, struct resume_from_snapshot_args *uap)
{
    return (kern_resume_from_snapshot(td, uap->pid, uap->threadid, uap->ctx));
}





