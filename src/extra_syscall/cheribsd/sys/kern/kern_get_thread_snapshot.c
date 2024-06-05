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

int	kern_get_thread_snapshot(struct thread *td, pid_t pid, int threadid, struct thread_snapshot *__capability ctx) {

    struct proc *p;
    struct thread *t;
    struct thread_snapshot ctx2;
    int error;

    // find proc
    p = pfind(pid);
    if (p == NULL)
        return ESRCH;
    
    PROC_UNLOCK(p);
    log(LOG_WARNING, "Debug: proc is %p\n", p);

    // find thread
    t = tdfind(threadid, pid);
    if (t == NULL) {
        PROC_UNLOCK(p);
        return ESRCH;
    }

    log(LOG_WARNING, "Debug: thread is %p\n", t);

    thread_lock(t);

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

    error = copyout(&ctx2, ctx, sizeof(struct thread_snapshot));
    PROC_UNLOCK(p);

    log(LOG_WARNING, "Debug: error is %d\n", error);

    return 0;
}

int sys_get_thread_snapshot(struct thread *td, struct get_thread_snapshot_args *uap)
{
    return (kern_get_thread_snapshot(td, uap->pid, uap->threadid, uap->ctx));
}






int	kern_resume_from_snapshot(struct thread *td, void *__capability stack, size_t stack_size, struct thread_snapshot *__capability ctx) {


    struct thread_snapshot ctx_in;
    int error = copyin(ctx, &ctx_in, sizeof(ctx_in));
    if (error) {
        return error;
    }


    log(LOG_WARNING, "stack: %p\n", stack);
    log(LOG_WARNING, "stack_size: %p\n", stack_size);

    int fd_stack = open("stack_dump.bin", O_RDWR);
    if (fd_stack == -1) {
        log(LOG_WARNING, "open_FAILED ???\n");
        return -1;
    }
    char *addr = mmap(stack, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd_stack, 0);
    if (addr == MAP_FAILED) {
        log(LOG_WARNING, "MAP_FAILED ???\n");
        close(fd_stack);
        return -1;
    }


    extern void recover_snapshot(void *);
    recover_snapshot((void *)&ctx_in);

    return 0;
}

int sys_resume_from_snapshot(struct thread *td, struct resume_from_snapshot_args *uap)
{
    return (kern_resume_from_snapshot(td, uap->stack, uap->stack_size, uap->ctx));
}