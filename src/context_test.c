#include "monitor.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sys/snapshot.h>

void *__capability global_sealcap;

void print_stack_info() {
    pthread_t self = pthread_self();
    pthread_attr_t attr;
    size_t stack_size;
    void* stack_addr;
    pthread_attr_init(&attr);
    pthread_attr_get_np(self, &attr);
    pthread_attr_getstacksize(&attr, &stack_size);
    pthread_attr_getstack(&attr, &stack_addr, &stack_size);
    printf("Stack address: %p\n", stack_addr);
    printf("Stack size: %zu bytes\n", stack_size);
    pthread_attr_destroy(&attr);
}


void thread_get_context(void *argv) {
    pthread_detach(pthread_self());
    int cid = global_cid;
    struct c_thread *ct = cvms[cid].threads;

    struct sigaction sa;
    sa.sa_sigaction = cvm_dumping;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction");
        return ;
    }

    struct itimerval timer;
    timer.it_value.tv_sec = 3;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = HEARTBEAT_TIMEOUT_SEC;
    timer.it_interval.tv_usec = HEARTBEAT_TIMEOUT_USEC;
    if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
        perror("setitimer");
        return ;
    }

    printf("3 pthread_getthreadid_np(): %d\n", pthread_getthreadid_np());
    printf("3 threadid: %d\n", threadid);

    //waiting for signal
    while(1) {
        sleep(1);
    }
}

void *__capability invalid_to_valid(void *__capability elem) {
    void *__capability valid_cap;
    int ptr_type = 0; //ddc: 0 , pcc: 1
    if((cheri_getperm(elem) & CHERI_PERM_EXECUTE) != 0) {
        //printf("pcc\n");
        ptr_type = 1;
    }

    if(ptr_type == 0) {
        if(cheri_getbase(elem) == 0) {
            valid_cap = cheri_getdefault();
            valid_cap = cheri_setoffset(valid_cap, 0);
            valid_cap = cheri_ptrperm(valid_cap, cheri_getlength(elem), cheri_getperm(elem));
        }
        else {
            valid_cap = cheri_ptrperm((void *)cheri_getbase(elem), cheri_getlength(elem), cheri_getperm(elem));
        }
    }
    else {
        if(cheri_getbase(elem) == 0) {
            valid_cap = cheri_getpcc();
            valid_cap = cheri_setoffset(valid_cap, 0);
        }
        else {
            valid_cap = cheri_getpcc();
            valid_cap = cheri_setoffset(valid_cap, 0);
            valid_cap = cheri_codeptrperm(cheri_getbase(elem), cheri_getlength(elem), cheri_getperm(elem));
        }
    }

    valid_cap = cheri_setoffset(valid_cap, cheri_getoffset(elem));
    valid_cap = cheri_setflags(valid_cap, cheri_getflags(elem));

    if(cheri_getsealed(elem)) {
        //printf("cheri_getsealed :  ");
        //CHERI_CAP_PRINT(valid_cap);
        if(cheri_gettype(elem) == 0xfffffffffffffffe) {
            valid_cap = cheri_sealentry(valid_cap);
        }
        else {
            valid_cap = cheri_seal(valid_cap, global_sealcap);
        }
    }
    return valid_cap;
}

void set_cap_info(void *addr, size_t size) {
    uintcap_t *stack_ptr = (uintcap_t *)(addr);
    uintcap_t *ptr = (uintcap_t *)(addr);
    for (int i=0; i<stack_cap_tags_sparse_now_length; i++) {
        int pos = stack_cap_tags_sparse[i];
        if(cheri_getperm((void *__capability)(stack_ptr[pos])) == 0) {
            printf("set_cap_info error: perm = 0 !!!!!\n\n\n\n\n");
            CHERI_CAP_PRINT(stack_ptr[pos]);
            continue;
        }
        void * __capability valid_cap;
        valid_cap = invalid_to_valid((void *__capability)(stack_ptr[pos]));
        ptr[pos] = valid_cap;
    }
}

void suspend_user_cVM() {
    struct thread_snapshot ctx;
    ctx.kernel_debug = DEBUG;
    ctx.lower_bound = 0;
    ctx.upper_bound = ULONG_MAX - 1;
    ctx.seq_number = 0;
    void * __capability cap_ptr = cheri_ptrperm(&ctx, 1000000000, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE \
    | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL | CHERI_PERMS_HWALL);

    while(1) {
        get_thread_snapshot(SUSPEND_THREAD, threadid, cap_ptr); // suspend
        if(ctx.suspend_flag == -1) {
            break;
        }
        usleep(100000);
        printf("try to suspend master app\n");
    }
}

void resume_user_cVM() {
    struct thread_snapshot ctx;
    ctx.kernel_debug = DEBUG;
    ctx.lower_bound = 0;
    ctx.upper_bound = ULONG_MAX - 1;
    ctx.seq_number = 0;
    void * __capability cap_ptr = cheri_ptrperm(&ctx, 1000000000, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE \
    | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL | CHERI_PERMS_HWALL);
    get_thread_snapshot(RESUEM_THREAD, threadid, cap_ptr); // suspend
    printf("resume_user_cVM: ignore ERROR in resume_syscall, this is ok. \n");
}


void thread_resume(int resume_flag) {
    pthread_detach(pthread_self());

#if DEBUG
    printf("resume_flag: %d\n", resume_flag);
#endif
    suspend_user_cVM();

    int cid = global_cid;
    struct c_thread *ct = cvms[cid].threads;
    pid_t pid = getpid();
    void * __capability cap_ptr;
    struct thread_snapshot ctx;
	size_t sealcap_size = sizeof(ct[0].sbox->box_caps.sealcap);

#if __FreeBSD__
	if(sysctlbyname("security.cheri.sealcap", &global_sealcap, &sealcap_size, NULL, 0) < 0) {
		printf("sysctlbyname(security.cheri.sealcap)\n");
		while(1) ;
	}
#else
	printf("sysctlbyname security.cheri.sealcap is not implemented in your OS\n");
#endif

    int tag_array[REG_NUM];

    if(resume_flag == RESUME_FROM_SNAPSHOT) {
        int fd = open("snapshot/context_dump.bin", O_RDWR);
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
        host_cap_file_resume();
        resume_fd_list_from_snapshot();
    }
    else {
        memcpy((void *)(&ctx), backup_context_buffer, sizeof(struct thread_snapshot));
        memcpy((void *)(&tag_array), (backup_context_buffer + sizeof(struct thread_snapshot)), sizeof(tag_array));
        host_cap_file_resume_from_memory();
    }

#if DEBUG
    printf("cvm_resume thread context end\n");
#endif

    uintcap_t *ptr = (uintcap_t *)(&ctx.frame.tf_ra);
    for(int i=0;i<REG_NUM;i++) {
        void *__capability elem = (void *__capability)(ptr[i]);
        #if DEBUG
            printf("[%d] origin tag: %d\n", i, tag_array[i]);
            CHERI_CAP_PRINT(elem);
        #endif
        if(tag_array[i] == 0) {
            continue;
        }
        void * __capability valid_cap;
        valid_cap = invalid_to_valid(elem);
        ptr[i] = valid_cap;
    }

#if DEBUG
    printf("read registers end\n");
#endif

    ctx.kernel_debug = DEBUG;
    cap_ptr = cheri_ptrperm(&ctx, 1000000000, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE \
    | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL | CHERI_PERMS_HWALL);

#if DEBUG
    CHERI_CAP_PRINT(cap_ptr); 
#endif

    if(resume_flag == RESUME_FROM_SNAPSHOT) {
        int fd_stack = open("snapshot/stack_dump.bin", O_RDWR);
        if (fd_stack == -1) {
            perror("open");
            exit(EXIT_FAILURE);
        }
        char *addr = mmap(ct->stack, ct->stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd_stack, 0);
        if (addr == MAP_FAILED) {
            perror("mmap ct->stack error");
            close(fd_stack);
            exit(EXIT_FAILURE);
        }
        close(fd_stack);

        stack_cap_tags_sparse_size = get_filesize("snapshot/stack_cap_tags.bin")/sizeof(int);
        stack_cap_tags_sparse_now_length = stack_cap_tags_sparse_size;
        stack_cap_tags_sparse = (int *)malloc(stack_cap_tags_sparse_size* sizeof(int));
        if(stack_cap_tags_sparse == NULL) {
            perror("malloc stack_cap_tags_sparse");
            exit(EXIT_FAILURE);
        }

        int fd3 = open("snapshot/stack_cap_tags.bin", O_RDWR);
        if (fd3 == -1) {
            perror("open stack_cap_tags.bin error");
            exit(EXIT_FAILURE);
        }
        if (read(fd3, (void *)stack_cap_tags_sparse, stack_cap_tags_sparse_size* sizeof(int)) == -1) {
            perror("read stack_cap_tags");
            close(fd3);
            exit(EXIT_FAILURE);
        }
        close(fd3);
#if HEAP_SNAPSHOT
        resume_heap_from_disk();
#endif
    }
    else {
        char *addr = mmap(ct->stack, ct->stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED) {
            perror("mmap ct->stack error");
            exit(EXIT_FAILURE);
        }
        memcpy((void *)addr, backup_stack_buffer, ct->stack_size);
#if HEAP_SNAPSHOT
        resume_heap_from_memory();
#endif
    }

    set_cap_info(ct->stack, ct->stack_size);
    resume_from_snapshot(pid, threadid, cap_ptr); // syscall
    resume_user_cVM();
    printf("resume_from_snapshot over\n");
}

// single thread
void capture_or_resume(int no) {
    print_stack_info();

    init_fd_store();
    
	int ret = -1;
	pthread_t timerid;

    if(no == NO_RESUME)
	    ret = pthread_create(&timerid, NULL, (void *)thread_get_context, NULL); 
    else if(no == RESUME_FROM_SNAPSHOT || no == RESUME_FROM_MEMORY)
	    ret = pthread_create(&timerid, NULL, (void *)thread_resume, (void *)(no));
    else {
        printf("capture_or_resume failed! error no:%d\n", no);
        exit(-1);
    }

	if(ret != 0) {
		printf("pthread_create failed!ret=%d err=%s\n", ret, strerror(ret));
	}

    mask_signal(SIGALRM);
}

