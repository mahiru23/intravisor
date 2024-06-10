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

    // find proc
    /*p = pfind(pid);
    if (p == NULL)
        return ESRCH;
    
    PROC_UNLOCK(p);*/
    p = td->td_proc;

    pid_t pid = p->p_pid;


    log(LOG_WARNING, "Debug: proc is %p\n", p);
    // find thread
    t = tdfind(threadid, pid);
    if (t == NULL) {
        PROC_UNLOCK(p);
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

    PROC_LOCK(p);



    log(LOG_WARNING, "cheri_getpcc is \n");
    CHERI_CAP_PRINT_KERN(cheri_getpcc());

    thread_lock(t);

    
    log(LOG_WARNING, "Debug: t->td_kstack is %lx\n", (unsigned long)(t->td_kstack));
    //log(LOG_WARNING, "Debug: t->td_kstack is \n");
    //CHERI_CAP_PRINT_KERN(t->td_kstack);

    

    log(LOG_WARNING, "Debug: t->td_kstack_pages is %d\n", t->td_kstack_pages);

    log(LOG_WARNING, "Debug: t->td_frame is %p\n", t->td_frame);

    log(LOG_WARNING, "Debug: t->td_frame.tf_sepc = %lx\n", (unsigned long)t->td_frame->tf_sepc);
    log(LOG_WARNING, "Debug: t->td_frame.tf_sp = %lx\n", (unsigned long)t->td_frame->tf_sp);
    log(LOG_WARNING, "Debug: t->td_frame.tf_ddc = %lx\n", (unsigned long)t->td_frame->tf_ddc);
    log(LOG_WARNING, "Debug: t->td_frame.tf_ra = %lx\n", (unsigned long)t->td_frame->tf_ra);

    memcpy(&(ctx2.frame), t->td_frame, sizeof(struct trapframe)); // context
    // memory ...?

    log(LOG_WARNING, "Debug: ctx2.frame.tf_sp = %lx\n", (unsigned long)ctx2.frame.tf_sp);

    thread_unlock(t);

    log(LOG_WARNING, "Debug: ctx2 len = %lu\n", sizeof(ctx2));
    log(LOG_WARNING, "Debug: ctx2 len = %p\n", &ctx2);
    log(LOG_WARNING, "Debug: VM_MAXUSER_ADDRESS = %lx\n", VM_MAXUSER_ADDRESS);
    log(LOG_WARNING, "Debug: ctx = %p\n", (__cheri_fromcap void *)ctx);

    CHERI_CAP_PRINT_KERN(ctx);
    CHERI_CAP_PRINT_KERN(cheri_getdefault());
    

    /*void *__capability ccap;
	ccap = cheri_ptrperm((int *)(CHERI_CAP_KERN_BASE), (size_t)(CHERI_CAP_KERN_LENGTH), CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL | CHERI_PERMS_HWALL);
    ccap = cheri_setaddress(ccap, (unsigned long) (cheri_getoffset(ctx)));
    CHERI_CAP_PRINT_KERN(ccap);*/
    

    // copyout to userspace
    unsigned long ptr = cheri_getaddress(ctx);
    log(LOG_WARNING, "Debug: ptr = %lu\n", ptr);

    //memcpy(&ctx, &ctx2, sizeof(ctx2));

    error = copyoutcap(&ctx2, ctx, sizeof(struct thread_snapshot));
    PROC_UNLOCK(p);

    log(LOG_WARNING, "Debug: error is %d\n", error);

    return 0;
}

int sys_get_thread_snapshot(struct thread *td, struct get_thread_snapshot_args *uap)
{
    return (kern_get_thread_snapshot(td, uap->pid, uap->threadid, uap->ctx));
}



int	kern_resume_from_snapshot(struct thread *td, pid_t pid, int threadid, struct thread_snapshot *__capability ctx) {
    

    struct proc *p;
    //struct pcb pcbx;
    struct thread *t;

    struct thread_snapshot ctx_in;
    int error = copyincap(ctx, &ctx_in, sizeof(ctx_in));
    if (error) {
        return error;
    }

    p = td->td_proc;
    // find thread
    t = tdfind(threadid, pid);
    if (t == NULL) {
        //PROC_UNLOCK(p);
        log(LOG_WARNING, "tdfind error\n");
        return ESRCH;
    }

    log(LOG_WARNING, "tdfind ok\n");

    
    log(LOG_WARNING, "Debug: thread is %p\n", t);

    //PROC_UNLOCK(p);
    //thread_lock(t);
    //thread_suspend_one(t);
    //PROC_UNLOCK(p);


    log(LOG_WARNING, "t->td_frame start\n");

    /*reg*/

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
    t->td_frame->tf_stval = ctx_in.frame.tf_stval;
    t->td_frame->tf_scause = ctx_in.frame.tf_scause;

    log(LOG_WARNING, "t->td_frame ok\n");

    /*......*/
    // update stack here?
    //t->td_kstack

    /*makectx(t->td_frame, &pcbx);

    log(LOG_WARNING, "makectx ok\n");
    savectx(&pcbx);

    log(LOG_WARNING, "savectx ok\n");*/

    //thread_unsuspend(p);

    //thread_unlock(t);
    PROC_UNLOCK(p);

    log(LOG_WARNING, "over\n");


    return 0;
}






int sys_resume_from_snapshot(struct thread *td, struct resume_from_snapshot_args *uap)
{
    return (kern_resume_from_snapshot(td, uap->pid, uap->threadid, uap->ctx));
}





