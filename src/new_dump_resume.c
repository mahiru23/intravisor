#include "monitor.h"
#include <pthread_np.h>

#define DEBUG 1

int replica_flag = 0;
void * __capability global_cap_ptr;
bool stack_cap_tags[32768]; // max_stack_size = 0x80000

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int is_paused = 0;
pthread_t global_pid;

void pause_thread() {
    pthread_mutex_lock(&mutex);
    is_paused = 1;
    pthread_mutex_unlock(&mutex);
}

void resume_thread() {
    pthread_mutex_lock(&mutex);
    is_paused = 0;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);
}


int is_capability(void *ptr) {
    int res = cheri_gettag((void * __capability)(ptr));
    return res;
}

void get_cap_info(void *stack, size_t size) {
    uintcap_t *stack_ptr = (uintcap_t *)(stack);
    int elem_len = sizeof(uintcap_t *) * 2; // cap = sizeof(void *)*2

#if DEBUG
    printf("size: %d\n", size);
    printf("elem_len: %d\n", elem_len);
    printf("check cap nums: %d\n", size / sizeof(uintcap_t *));
#endif

    memset(stack_cap_tags, 0, sizeof(stack_cap_tags));

    int sum_cap = 0;
    for (size_t i = 0; i < size / elem_len; ++i) {
        if (is_capability(stack_ptr[i])) {
            /*printf("cap_1: %d\n", i);
            void *__capability elem = (void *__capability)(stack_ptr[i]);
            CHERI_CAP_PRINT(elem);*/
            stack_cap_tags[i] = 1;
            sum_cap++;
        } else {
            stack_cap_tags[i] = 0;
        }
    }
#if DEBUG
    printf("sum_cap: %d\n", sum_cap);
#endif
}

int write_to_stackfile(int fd, void *addr, int size, int page) {
    if (lseek(fd, page*PAGE_SIZE, SEEK_SET) == -1) {
        perror("write_to_stackfile lseek");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (write(fd, addr, size) == -1) {
        perror("write_to_stackfile write");
        close(fd);
        exit(EXIT_FAILURE);
    }

    /*------------------------------------------*/
    /*remap*/

    off_t page_offset = 0; 
    if (munmap(addr + page_offset, PAGE_SIZE) == -1) {
        perror("munmap page error");
        close(fd);
        return EXIT_FAILURE;
    }

    char *new_addr = mmap(addr + page_offset, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, page * PAGE_SIZE);
    if (new_addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return EXIT_FAILURE;
    }

    /*------------------------------------------*/
    return 0;
}

char dirty_page_map[PAGE_NUM];

void stack_dirty_page_update(struct c_thread *ct) {

    int fd = open("stack_dump.bin", O_RDWR, 0777);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    int pages = (ct->stack_size) / PAGE_SIZE;

    get_dirty_page_num(ct->stack_size, pages, ct->stack);

    /*char *vec = (char *)malloc(pages);
    if (vec == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }*/
    memset(dirty_page_map, 0, sizeof(dirty_page_map));
    if (mincore(ct->stack, ct->stack_size, dirty_page_map) == -1) {
        perror("mincore");
        //free(vec);
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < pages; i++) {
        if (dirty_page_map[i] & MINCORE_MODIFIED) {
            write_to_stackfile(fd, ct->stack+i*PAGE_SIZE, PAGE_SIZE, i);
        }
    }

    //free(vec);

    /*if (msync(ct->stack, ct->stack_size, MS_SYNC) == -1) {
        perror("msync");
        exit(EXIT_FAILURE);
    }*/

    get_dirty_page_num(ct->stack_size, pages, ct->stack);

	size_t sealcap_size = sizeof(ct[0].sbox->box_caps.sealcap);

#if __FreeBSD__
	if(sysctlbyname("security.cheri.sealcap", &global_sealcap, &sealcap_size, NULL, 0) < 0) {
		printf("sysctlbyname(security.cheri.sealcap)\n");
		while(1) ;
	}
#else
	printf("sysctlbyname security.cheri.sealcap is not implemented in your OS\n");
#endif

    set_cap_info(ct->stack, ct->stack_size);

    get_dirty_page_num(ct->stack_size, pages, ct->stack);

    close(fd); 
    
}

// replica_flag is a state machine here
// TODO: but it seems not good, so disable suspend & resume syscall here
int cvm_dumping() {

    int cid = 16; // todo: global or arg
    struct c_thread *ct = cvms[cid].threads;
    //pthread_mutex_lock(&ct->sbox->ct_lock); // thread_lock
    struct thread_snapshot ctx;
    void * __capability cap_ptr = cheri_ptrperm(&ctx, 1000000000, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE \
    | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL | CHERI_PERMS_HWALL);

#if DEBUG
    CHERI_CAP_PRINT(cap_ptr);
    printf("pthread_mutex_lock, cid: %d\n", cid);
    printf("pthread_getthreadid_np(): %d\n", pthread_getthreadid_np());
    printf("threadid: %d\n", threadid);
#endif

    pause_thread();
    get_thread_snapshot(SUSPEND_THREAD, threadid, cap_ptr);

    int ret = get_thread_snapshot(CAPTURE_SNAPSHOT, threadid, cap_ptr);
    unsigned long pc_addr = cheri_getaddress(ctx.frame.tf_sepc);
    unsigned long lower_bound = comp_to_mon(ct->sbox->base, ct->sbox);
    unsigned long upper_bound = comp_to_mon(ct->sbox->top, ct->sbox);

#if DEBUG
    printf("get_thread_snapshot(CAPTURE_SNAPSHOT, threadid, cap_ptr);, cid: %d\n", cid);
    CHERI_CAP_PRINT(ctx.frame.tf_ra);
    CHERI_CAP_PRINT(ctx.frame.tf_sepc);
    printf("replica_flag: %d\n", replica_flag);
    printf("pc_addr: %lx\n", pc_addr);
    printf("lower_bound: %lx\n", lower_bound);
    printf("upper_bound: %lx\n", upper_bound);
#endif

    if(replica_flag == 2) { // in intravisor userspace
        //heartbeat(-1);
        ;
    }
    else if(pc_addr >= lower_bound && pc_addr <= upper_bound) { // in sandbox
        //heartbeat(-1);
        ;
    }
    else { // in kernel
        heartbeat(-1);
        printf("in kernel\n");
        replica_flag = 1;
        //pthread_mutex_unlock(&ct->sbox->ct_lock);
        get_thread_snapshot(RESUEM_THREAD, threadid, cap_ptr);
        resume_thread();
        return 0;
    }

    int tag_array[33];
    memset(tag_array, 0, sizeof(tag_array));
    uintcap_t *ptr = (uintcap_t *)(&ctx.frame.tf_ra);
    for(int i=0;i<33;i++) {
        void *__capability elem = (void *__capability)(ptr[i]); // copyoutcap with tag
#if DEBUG
        printf("[%d]", i);
        CHERI_CAP_PRINT(elem);
#endif

        tag_array[i] = cheri_gettag(elem);
    }

    int fd = open("context_dump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (write(fd, &ctx, sizeof(struct thread_snapshot)) == -1) {
        perror("write thread_snapshot");
        close(fd);
        exit(EXIT_FAILURE);
    }
    if (write(fd, tag_array, sizeof(tag_array)) == -1) {
        perror("write tag_array");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);

#if DEBUG
    printf("thread_context end\n");
#endif
    int dirty_page_num = get_dirty_page_num(ct->stack_size, PAGE_NUM, ct->stack);

    get_cap_info(ct->stack, ct->stack_size);

    stack_dirty_page_update(ct);

    int fd3 = open("stack_cap_tags.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd3 == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (write(fd3, stack_cap_tags, sizeof(stack_cap_tags)) == -1) {
        perror("write stack_cap_tags");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd3); 

    printf("stack_cap_tags end\n");

    host_cap_file_dump();

    if(is_master & backup_valid_flag) {
        master_to_backup(ct, dirty_page_num);
    }

#if DEBUG
    //test suspend
    printf("test suspend start\n");
    //sleep(3);
    printf("test suspend end\n");
#endif
    
    if(replica_flag == 2) { // in intravisor userspace
        replica_flag = 0;
    }

    //pthread_mutex_unlock(&ct->sbox->ct_lock);
    get_thread_snapshot(RESUEM_THREAD, threadid, cap_ptr);

    //pthread_resume_np(global_pid);
    resume_thread();
    return 0;
}









