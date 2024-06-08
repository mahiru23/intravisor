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






int	kern_resume_from_snapshot(struct thread *td, void *__capability stack2, size_t stack_size, struct thread_snapshot *__capability ctx, void *__capability dumpstack, void *__capability sealcap) {
    
    
    //struct proc *p = td->td_proc;
    //PROC_LOCK(p);
    //thread_lock(td);
    

    vm_offset_t stack = (vm_offset_t)cheri_getaddress(stack2);

    
    //uintcap_t sealcap = td->td_frame->tf_ra;
    CHERI_CAP_PRINT_KERN(td->td_frame->tf_sp);

    uintcap_t test_cap;

    test_cap = td->td_frame->tf_sp;
    test_cap = cheri_setoffset(test_cap, cheri_getoffset(test_cap)+20);

    CHERI_CAP_PRINT_KERN(test_cap);
    CHERI_CAP_PRINT_KERN(td->td_frame->tf_sp);


    CHERI_CAP_PRINT_KERN(stack2);
    log(LOG_WARNING, "stack: %lx\n", (unsigned long)stack);
    log(LOG_WARNING, "stack_size: %lx\n", (unsigned long)stack_size);
    log(LOG_WARNING, "td_kstack: %lx\n", (unsigned long)(td->td_kstack));
    log(LOG_WARNING, "td_kstack_pages: %lx\n", (unsigned long)(td->td_kstack_pages));
    log(LOG_WARNING, "cheri_getpcc(): ");
    CHERI_CAP_PRINT_KERN(cheri_getpcc());
    //log(LOG_WARNING, "cheri_getpcc(): %lx\n", (unsigned long)cheri_getstack());

    log(LOG_WARNING, "cheri_getdefault(): ");
    CHERI_CAP_PRINT_KERN(cheri_getdefault());

    //log(LOG_WARNING, "cheri_getstack(): ");
    //CHERI_CAP_PRINT_KERN(cheri_getstack());
    

    
    struct thread_snapshot ctx_in;
    int error = copyincap(ctx, &ctx_in, sizeof(ctx_in));
    if (error) {
        return error;
    }
    CHERI_CAP_PRINT_KERN(ctx_in.frame.tf_sp);
    CHERI_CAP_PRINT_KERN(ctx_in.frame.tf_sepc);
    log(LOG_WARNING, "Debug: ctx.stack is \n");
    CHERI_CAP_PRINT_KERN(ctx_in.stack);

    uintcap_t *ptr = (uintcap_t *)(&ctx_in.frame.tf_ra);
    for(int i=0;i<33;i++) {
        void *__capability elem = (void *__capability)(ptr[i]);
        log(LOG_WARNING, "[%d]", i);
        CHERI_CAP_PRINT_KERN(elem);

        if(cheri_getperm(elem) == 0) {
            continue;
        }

        //unsigned long* base_addr = (unsigned long*)cheri_getbase(elem);

        long *__capability pcc_temp = cheri_getpcc();
        pcc_temp = cheri_setaddress(pcc_temp, cheri_getbase(elem));

        CHERI_CAP_PRINT_KERN(cheri_getpcc());
        CHERI_CAP_PRINT_KERN(pcc_temp);


        long *__capability valid_cap = cheri_ptrperm(pcc_temp, cheri_getlength(elem), cheri_getperm(elem));
        CHERI_CAP_PRINT_KERN(valid_cap);
        valid_cap = cheri_setoffset(valid_cap, cheri_getoffset(elem));
        //valid_cap = cheri_setoffset(valid_cap, cheri_getoffset(elem));
        if(cheri_getsealed(elem))
            valid_cap = cheri_seal(valid_cap, sealcap);
        
        CHERI_CAP_PRINT_KERN(valid_cap);
        ptr[i] = (uintcap_t)valid_cap;
        CHERI_CAP_PRINT_KERN(ptr[i]);
    }

    CHERI_CAP_PRINT_KERN(ctx_in.frame.tf_sp);
    CHERI_CAP_PRINT_KERN(ctx_in.frame.tf_sepc);
    log(LOG_WARNING, "Debug: ctx.stack is \n");

    //return 0;

    void *kernel_buffer;
    kernel_buffer = malloc(stack_size, M_TEMP, M_WAITOK);
    if (kernel_buffer == NULL) {
        log(LOG_WARNING, "malloc error\n");
        return ENOMEM;
    }
    // 从用户空间复制到内核缓冲区
    error = copyincap(dumpstack, kernel_buffer, stack_size);
    if (error) {
        log(LOG_WARNING, "copyin error %d\n", error);
        free(kernel_buffer, M_TEMP);
        return error;
    }
    /*error = copyoutcap(kernel_buffer, stack2, stack_size);
    if (error) {
        log(LOG_WARNING, "copyout error %d\n", error);
        free(kernel_buffer, M_TEMP);
        return error;
    }
    free(kernel_buffer, M_TEMP);*/
    log(LOG_WARNING, "stack resume ok\n");


    //extern void recover_snapshot(void *);
    recover_snapshot((void *)&(ctx_in.frame));

    return 0;
}

int sys_resume_from_snapshot(struct thread *td, struct resume_from_snapshot_args *uap)
{
    return (kern_resume_from_snapshot(td, uap->stack, uap->stack_size, uap->ctx, uap->dumpstack, uap->sealcap));
}



int	kern_resume_from_snapshot_another_thread(struct thread *td, pid_t pid, int threadid, struct thread_snapshot *__capability ctx) {
    

    struct proc *p;
    struct pcb *pcb;
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
        PROC_UNLOCK(p);
        return ESRCH;
    }



    thread_suspend_one(t);




    log(LOG_WARNING, "Debug: thread is %p\n", t);
    thread_lock(t);

    /*reg*/
    t->td_frame->tf_sp = ctx_in.frame.tf_sp;
    /*......*/
    // update stack here?
    //t->td_kstack





    makectx(td_frame, pcb);
    savectx(pcb);


    thread_resume(t);

    thread_unlock(t);
    PROC_UNLOCK(p);



    return 0;
}



