#include "monitor.h"

#define DEBUG 1

ucontext_t global_context;
struct c_thread * global_ct;


void *__capability global_sealed_pcc;
void *__capability global_sealed_ddc;
void *__capability global_ddc;
unsigned long gloflag;

char *global_addr_fixed_resume;

int cvm_dumping(int cid) {
    struct c_thread *ct = cvms[cid].threads;
    //struct c_thread *ct, void * __capability pcc, void * __capability ddc, void * __capability ddc2,unsigned long s0,unsigned long ra,unsigned long sp
    //printf("cvm_dumping\n");
    #if DEBUG
            printf("cvm_dumping, cid: %d\n", cid);
    #endif

    // thread_lock
    pthread_mutex_lock(&ct->sbox->ct_lock);
    // proc/thread struct lock with extra syscall

    printf("pthread_mutex_lock, cid: %d\n", cid);

    struct thread_snapshot ctx;
    pid_t pid = getpid();
    //lwpid_t threadid = pthread_getthreadid_np();
    void * __capability cap_ptr = cheri_ptrperm(&ctx, 1000000000, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE \
    | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL | CHERI_PERMS_HWALL);
    #if DEBUG
            CHERI_CAP_PRINT(cap_ptr);
    #endif
    int ret = get_thread_snapshot(pid, threadid, cap_ptr);

    CHERI_CAP_PRINT(ctx.frame.tf_ra);
    CHERI_CAP_PRINT(ctx.frame.tf_sp);




    int tag_array[33];
    memset(tag_array, 0, sizeof(tag_array));
    uintcap_t *ptr = (uintcap_t *)(&ctx.frame.tf_ra);
    for(int i=0;i<33;i++) {
        void *__capability elem = (void *__capability)(ptr[i]);
        printf("[%d]", i);
        CHERI_CAP_PRINT(elem);

        tag_array[i] = cheri_gettag(elem);
    }

    int fd = open("context_dump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (write(fd, &ctx, sizeof(struct thread_snapshot)) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if (write(fd, tag_array, sizeof(tag_array)) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
    #if DEBUG
            printf("thread_context end\n");

    #endif


    int fd2 = open("stack_dump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd2 == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (write(fd2, ct->stack, ct->stack_size) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd2); 


    host_cap_file_dump();

    pthread_mutex_unlock(&ct->sbox->ct_lock);

    exit(-1);


    return 0;
}


void resume_and_enter(struct c_thread *ct, unsigned long v1, unsigned long v2, unsigned long v3) {
    int fd = open("stack_dump.bin", O_RDWR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
	__asm__ __volatile__("cmove cs3, %0;" :: "C"(ct->sbox->box_caps.sealed_ret_from_mon) : "memory");
	__asm__ __volatile__("cmove cs4, %0;" :: "C"(ct->sbox->box_caps.sealed_datacap) : "memory");
	__asm__ __volatile__("cmove cs5, %0;" :: "C"(ct->sbox->box_caps.dcap) : "memory");
    __asm__ __volatile__("cmove cs9, %0;" :: "C"(ct->c_tp) : "memory");
	__asm__ __volatile__("mv s6, %0;" :: "r"(v1) : "memory");
	__asm__ __volatile__("mv s7, %0;" :: "r"(v2) : "memory");
	__asm__ __volatile__("mv s8, %0;" :: "r"(v3) : "memory");
    char *addr = mmap(ct->stack, ct->stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (addr == MAP_FAILED) {
        printf("???????????????\n");
        close(fd);
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    __asm__ __volatile__("cmove ctp, cs9;" ::  : "memory");
	__asm__ __volatile__("mv ra, s7;" ::  : "memory");
	__asm__ __volatile__("mv sp, s8;" ::  : "memory");
	__asm__ __volatile__("mv s0, s6;" ::  : "memory");
	__asm__ __volatile__("cspecialw	ddc, cs5;" ::  : "memory");
	__asm__ __volatile__("CInvoke cs3, cs4;" ::  : "memory");
}

void context_set(struct c_thread *ct, struct thread_snapshot ctx) {
    //global_context;

#if (defined riscv_hyb) || (defined riscv)

    global_context.uc_mcontext.mc_gpregs.gp_ra = ctx.frame.tf_ra;
    global_context.uc_mcontext.mc_gpregs.gp_sp = ctx.frame.tf_sp;
    global_context.uc_mcontext.mc_gpregs.gp_gp = ctx.frame.tf_gp;
    global_context.uc_mcontext.mc_gpregs.gp_tp = ctx.frame.tf_tp;
    for(int i=0;i<7;i++) {
        global_context.uc_mcontext.mc_gpregs.gp_t[i] = ctx.frame.tf_t[i];
    }
    for(int i=0;i<12;i++) {
        global_context.uc_mcontext.mc_gpregs.gp_s[i] = ctx.frame.tf_s[i];
    }
    for(int i=0;i<8;i++) {
        global_context.uc_mcontext.mc_gpregs.gp_a[i] = ctx.frame.tf_a[i];
    }

    global_context.uc_mcontext.mc_gpregs.gp_sepc = ctx.frame.tf_sepc;
    global_context.uc_mcontext.mc_gpregs.gp_sstatus = ctx.frame.tf_sstatus;


    //global_context->uc_mcontext.mc_gpregs.gp_sp
# else
    printf("? only RISC-V\n");
    while(1) {
        sleep();
    }

#endif
}

void bind_stack(struct c_thread *ct) {
    int fd = open("stack_dump.bin", O_RDWR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

            printf("stack: %p\n", ct->stack);
            printf("stack_size: %p\n", ct->stack_size);

    char *addr = mmap(ct->stack, ct->stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (addr == MAP_FAILED) {
        printf("???????????????\n");
        close(fd);
        perror("mmap");
        exit(EXIT_FAILURE);
    }
}

struct thread_snapshot ctx;

void cvm_resume(struct c_thread *ct) {
    int cid = 16;

    void *__capability sealcap;
	size_t sealcap_size = sizeof(ct[0].sbox->box_caps.sealcap);
#if __FreeBSD__
	if(sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size, NULL, 0) < 0) {
		printf("sysctlbyname(security.cheri.sealcap)\n");
		while(1) ;
	}
#else
	printf("sysctlbyname security.cheri.sealcap is not implemented in your OS\n");
#endif

    int tag_array[33];
    int fd = open("context_dump.bin", O_RDWR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (read(fd, &ctx, sizeof(struct thread_snapshot)) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if (read(fd, &tag_array, sizeof(tag_array)) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
    #if DEBUG
            printf("cvm_resume thread context end\n");
    #endif

    printf("%p\n", ctx.frame.tf_ra);
    CHERI_CAP_PRINT(ctx.frame.tf_ra);

    
    uintcap_t *ptr = (uintcap_t *)(&ctx.frame.tf_ra);
    for(int i=0;i<33;i++) {
        /*if(tag_array[i] == 0) {
            continue;
        }*/
        void *__capability elem = (void *__capability)(ptr[i]);
        printf("[%d]", i);
        CHERI_CAP_PRINT(elem);

        if(cheri_getperm(elem) == 0) {
            //ptr[i] = cheri_setoffset(elem, cheri_getoffset(elem));
            continue;
        }

        void *__capability valid_cap = cheri_ptrperm((void *)cheri_getbase(elem), cheri_getlength(elem), cheri_getperm(elem));

        valid_cap = cheri_setoffset(valid_cap, cheri_getoffset(elem));

        if(cheri_getsealed(elem))
            valid_cap = cheri_seal(valid_cap, sealcap);

        ptr[i] = valid_cap;
        CHERI_CAP_PRINT(valid_cap);


        //printf("Before modification: tf_element[%zu] = %p\n", i, (void*)ptr[i]);
        
         printf("%p\n", elem);

        //tag_array[i] = cheri_gettag((void * __capability)((unsigned long)(&ctx.frame)+16*i));


    }

    host_cap_file_resume();
    context_set(ct, ctx);
    //resume_and_enter(ct, );
    printf("global_context.uc_mcontext.mc_gpregs.gp_sp: %lx\n", global_context.uc_mcontext.mc_gpregs.gp_sp);
    printf("(unsigned long)global_context.uc_mcontext.mc_gpregs.gp_sp: %lx\n", (unsigned long)global_context.uc_mcontext.mc_gpregs.gp_sp);





    void *__capability ccap;
    ccap = pure_codecap_create((void *) ct[0].sbox->cmp_begin, (void *) ct[0].sbox->cmp_end, cvms[cid].clean_room);
    void *__capability dcap = datacap_create((void *) ct[0].sbox->cmp_begin, (void *) ct[0].sbox->cmp_end, cvms[cid].clean_room);

    printf("ctx.frame.tf_sepc:%p\n", ctx.frame.tf_sepc);
    printf("ctx.frame.tf_ra:%p\n", ctx.frame.tf_ra);
    printf("ctx.frame.tf_sp:%p\n", ctx.frame.tf_sp);
    printf("ctx.frame.tf_sp:%lx\n", (unsigned long)ctx.frame.tf_sp);
    printf("ctx.frame.tf_tp:%p\n", ctx.frame.tf_tp);
    printf("ctx.frame.tf_ddc:%p\n", ctx.frame.tf_ddc);

    printf("cmp_begin:%p\n", (void *) ct[0].sbox->cmp_begin);
    printf("cmp_end:%p\n", (void *) ct[0].sbox->cmp_end);

    global_ddc = dcap;
    ccap = cheri_setaddress(ccap, (unsigned long)(ctx.frame.tf_sepc)-20);

    CHERI_CAP_PRINT(ccap);

	global_sealed_ddc = cheri_seal(dcap, sealcap);
	global_sealed_pcc = cheri_seal(ccap, sealcap);
    /*global_sealed_ddc = dcap;
	global_sealed_pcc = ccap;*/

#if DEBUG
	printf("ca0: global_sealed_pcc\n");
	CHERI_CAP_PRINT(global_sealed_pcc);

	printf("ca1: global_sealed_ddc\n");
	CHERI_CAP_PRINT(global_sealed_ddc);

	printf("ca2: global_ddc\n");
	CHERI_CAP_PRINT(global_ddc);
#endif


CHERI_CAP_PRINT(ctx.frame.tf_ddc);
printf("ctx.frame.tf_ddc:%lx\n", (unsigned long)ctx.frame.tf_ddc);
gloflag = (unsigned long)ctx.frame.tf_ddc;

printf("gloflag %lx\n", gloflag);

    global_ct = ct;
    //bind_stack(ct);

printf("ctx.frame.tf_ddc:%lx\n", (unsigned long)ctx.frame.tf_ddc);

ctx.frame.tf_sepc = global_sealed_pcc;
ctx.frame.tf_ddc = global_sealed_ddc;



#if DEBUG
	printf("ctx.frame.tf_sepc\n");
	CHERI_CAP_PRINT(ctx.frame.tf_sepc);

	printf("ctx.frame.tf_ddc\n");
	CHERI_CAP_PRINT(ctx.frame.tf_ddc);

#endif


//cheri_gettag((void *)((unsigned long)(&ctx.frame)+16*i));


    /*global_addr_fixed_resume = mmap(0x4000000, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (global_addr_fixed_resume == MAP_FAILED) {
        printf("???????????????\n");
        //close(fd_stack);
        perror("mmap");
        exit(EXIT_FAILURE);
    }*/

    /*memcpy(0x4000000, &global_context, sizeof(global_context));
    memcpy(0x4000000+0x4000, &global_sealed_pcc, sizeof(global_sealed_pcc));
    memcpy(0x4000000+0x5000, &global_sealed_ddc, sizeof(global_sealed_ddc));
    memcpy(0x4000000+0x6000, &global_ddc, sizeof(global_ddc));*/








    int fd_stack = open("stack_dump.bin", O_RDWR);
    if (fd_stack == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

            printf("stack: %p\n", ct->stack);
            printf("stack_size: %p\n", ct->stack_size);

    char *addr = mmap(ct->stack, ct->stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd_stack, 0);
    if (addr == MAP_FAILED) {
        printf("???????????????\n");
        close(fd_stack);
        perror("mmap");
        exit(EXIT_FAILURE);
    }


    if(gloflag == 0) {
        //printf("resume outside\n");
        //bind_stack(ct);
        //setcontext(global_context);
        __asm__ __volatile__("mv ra, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_ra) : "memory");
        __asm__ __volatile__("mv sp, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_sp) : "memory");
        __asm__ __volatile__("mv gp, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_gp) : "memory");
        __asm__ __volatile__("mv tp, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_tp) : "memory");

        __asm__ __volatile__("mv t0, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[0]) : "memory");
        __asm__ __volatile__("mv t1, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[1]) : "memory");
        __asm__ __volatile__("mv t2, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[2]) : "memory");
        __asm__ __volatile__("mv t3, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[3]) : "memory");
        __asm__ __volatile__("mv t4, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[4]) : "memory");
        __asm__ __volatile__("mv t5, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[5]) : "memory");
        __asm__ __volatile__("mv t6, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[6]) : "memory");

        __asm__ __volatile__("mv s0, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[0]) : "memory");
        __asm__ __volatile__("mv s1, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[1]) : "memory");
        __asm__ __volatile__("mv s2, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[2]) : "memory");
        __asm__ __volatile__("mv s3, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[3]) : "memory");
        __asm__ __volatile__("mv s4, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[4]) : "memory");
        __asm__ __volatile__("mv s5, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[5]) : "memory");
        __asm__ __volatile__("mv s6, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[6]) : "memory");
        __asm__ __volatile__("mv s7, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[7]) : "memory");
        __asm__ __volatile__("mv s8, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[8]) : "memory");
        __asm__ __volatile__("mv s9, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[9]) : "memory");
        __asm__ __volatile__("mv s10, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[10]) : "memory");
        __asm__ __volatile__("mv s11, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[11]) : "memory");

        __asm__ __volatile__("mv a0, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[0]) : "memory");
        __asm__ __volatile__("mv a1, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[1]) : "memory");
        __asm__ __volatile__("mv a2, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[2]) : "memory");
        __asm__ __volatile__("mv a3, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[3]) : "memory");
        __asm__ __volatile__("mv a4, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[4]) : "memory");
        __asm__ __volatile__("mv a5, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[5]) : "memory");
        __asm__ __volatile__("mv a6, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[6]) : "memory");
        __asm__ __volatile__("mv a7, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[7]) : "memory");
    }
    else {
        extern void cinv_resume();
        cinv_resume((void *)&ctx, global_ddc);
        exit(-1);


        //printf("resume inside\n");

        __asm__ __volatile__("mv ra, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_ra) : "memory");
        __asm__ __volatile__("mv sp, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_sp) : "memory");
        __asm__ __volatile__("mv gp, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_gp) : "memory");
        __asm__ __volatile__("mv tp, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_tp) : "memory");

        __asm__ __volatile__("mv t0, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[0]) : "memory");
        __asm__ __volatile__("mv t1, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[1]) : "memory");
        __asm__ __volatile__("mv t2, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[2]) : "memory");
        __asm__ __volatile__("mv t3, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[3]) : "memory");
        __asm__ __volatile__("mv t4, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[4]) : "memory");
        __asm__ __volatile__("mv t5, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[5]) : "memory");
        __asm__ __volatile__("mv t6, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_t[6]) : "memory");

        __asm__ __volatile__("mv s0, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[0]) : "memory");
        __asm__ __volatile__("mv s1, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[1]) : "memory");
        __asm__ __volatile__("mv s2, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[2]) : "memory");
        __asm__ __volatile__("mv s3, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[3]) : "memory");
        __asm__ __volatile__("mv s4, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[4]) : "memory");
        __asm__ __volatile__("mv s5, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[5]) : "memory");
        __asm__ __volatile__("mv s6, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[6]) : "memory");
        __asm__ __volatile__("mv s7, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[7]) : "memory");
        __asm__ __volatile__("mv s8, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[8]) : "memory");
        __asm__ __volatile__("mv s9, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[9]) : "memory");
        __asm__ __volatile__("mv s10, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[10]) : "memory");
        __asm__ __volatile__("mv s11, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_s[11]) : "memory");

        __asm__ __volatile__("mv a0, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[0]) : "memory");
        __asm__ __volatile__("mv a1, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[1]) : "memory");
        __asm__ __volatile__("mv a2, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[2]) : "memory");
        __asm__ __volatile__("mv a3, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[3]) : "memory");
        __asm__ __volatile__("mv a4, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[4]) : "memory");
        __asm__ __volatile__("mv a5, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[5]) : "memory");
        __asm__ __volatile__("mv a6, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[6]) : "memory");
        __asm__ __volatile__("mv a7, %0;" :: "r"(global_context.uc_mcontext.mc_gpregs.gp_a[7]) : "memory");
        
        //__asm__ __volatile__("cmove cs5, %0;" :: "C"(global_ddc) : "memory");
        __asm__ __volatile__("cspecialw	ddc, %0;" :: "C"(global_ddc) : "memory");
        __asm__ __volatile__("CInvoke %0, %1;" :: "C"(global_sealed_pcc), "C"(global_sealed_ddc) : "memory");

    }



}







