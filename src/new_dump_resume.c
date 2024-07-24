#include "monitor.h"
#include <pthread_np.h>

int seq_num = 0; // snapshot counter to analyse perf, != global_capture_count, count all epoch
int global_capture_count = 0; // only count suspend
double global_capture_time = 0;
pthread_mutex_t snapshot_mtx = PTHREAD_MUTEX_INITIALIZER;

/*TODO: this part should rewrite?*/
/*----------------------*/
// int replica_flag = 0; 
int *stack_cap_tags_sparse = NULL;
int stack_cap_tags_sparse_size;
int stack_cap_tags_sparse_now_length;
/*----------------------*/

int get_cap_info(void *stack, size_t size) {
    uintcap_t *stack_ptr = (uintcap_t *)(stack);
    int elem_len = sizeof(uintcap_t *) * 2; // cap = sizeof(void *)*2

#if DEBUG
    printf("size: %d\n", size);
    printf("elem_len: %d\n", elem_len);
    printf("check cap nums: %d\n", size / sizeof(uintcap_t *));
#endif

    memset(stack_cap_tags_sparse, 0, stack_cap_tags_sparse_size);
    int sum_cap = 0;

    // bitmap -> sparse array
    for (size_t i = 0; i < size / elem_len; ++i) {
        if (is_capability(stack_ptr[i])) {
            if(sum_cap >= stack_cap_tags_sparse_size) { // extend tag array
                int new_size = min(stack_cap_tags_sparse_size*2, STACK_CAP_LINE);
                char *new_stack_cap_tags_sparse = realloc(stack_cap_tags_sparse, new_size * sizeof(int));
                if(new_stack_cap_tags_sparse == NULL) {
                    perror("realloc backup_capfiles_buffer");
                    free(stack_cap_tags_sparse);
                    exit(EXIT_FAILURE);
                }
                stack_cap_tags_sparse = new_stack_cap_tags_sparse;
                stack_cap_tags_sparse_size = new_size;
            }
            stack_cap_tags_sparse[sum_cap] = i;
            sum_cap++;
        } else {
            //stack_cap_tags[i] = 0;
            ;
        }
    }
#if DEBUG
    printf("sum_cap: %d\n", sum_cap);
#endif
    stack_cap_tags_sparse_now_length = sum_cap;
    return sum_cap;
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

    /*off_t page_offset = 0; 
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
    }*/

    /*------------------------------------------*/
    return 0;
}

char dirty_page_map[PAGE_NUM];
char dirty_page_map_temp[PAGE_NUM];

int stack_dirty_page_update(struct c_thread *ct) {
    int dirty_page_num = 0;
    int pages = (ct->stack_size) / PAGE_SIZE;
    int fd = open("snapshot/stack_dump.bin", O_RDWR, 0777);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

#if DEBUG
    printf("before msync_manual: ");
    get_dirty_page_num(ct->stack_size, pages, ct->stack);
#endif

    memset(dirty_page_map, 0, sizeof(dirty_page_map));
    if (mincore(ct->stack, ct->stack_size, dirty_page_map) == -1) {
        perror("mincore");
        exit(EXIT_FAILURE);
    }

    // copy full stack at first loop (only once)
    if(full_copy_flag == 0) {
        full_copy_flag = 1;
        for (int i = 0; i < pages; i++) {
            dirty_page_map[i] |= MINCORE_MODIFIED;
        }
    }

    for (int i = 0; i < pages; i++) {
        if (dirty_page_map[i] & MINCORE_MODIFIED) {
            write_to_stackfile(fd, ct->stack+i*PAGE_SIZE, PAGE_SIZE, i);
            dirty_page_num++;
        }
    }
    if (msync_manual(ct->stack, ct->stack_size, dirty_page_map_temp) == -1) {
        perror("msync_manual");
        exit(EXIT_FAILURE);
    }

#if DEBUG
    printf("after msync_manual: ");
    get_dirty_page_num(ct->stack_size, pages, ct->stack);
#endif
    close(fd); 
    return dirty_page_num;
}

// replica_flag is a state machine here
// TODO: but it seems not good, so disable suspend & resume syscall here
int cvm_dumping() {

    pthread_mutex_lock(&snapshot_mtx);

    int cid = global_cid; // todo: arg?
    struct c_thread *ct = cvms[cid].threads;
    struct thread_snapshot ctx;
    ctx.kernel_debug = DEBUG;

    //pause_thread();
    //get_thread_snapshot(SUSPEND_THREAD, threadid, cap_ptr);

#if ANALYSE
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    unsigned long lower_bound = comp_to_mon(ct->sbox->base, ct->sbox);
    unsigned long upper_bound = comp_to_mon(ct->sbox->top, ct->sbox);

    ctx.lower_bound = lower_bound;
    ctx.upper_bound = upper_bound;
    seq_num++;
    ctx.seq_number = seq_num;
    
    void * __capability cap_ptr = cheri_ptrperm(&ctx, 1000000000, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE \
    | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL | CHERI_PERMS_HWALL);

    get_thread_snapshot(SUSPEND_AND_CAPTURE, threadid, cap_ptr); // suspend & capture
    unsigned long pc_addr = cheri_getaddress(ctx.frame.tf_sepc);

    if(ctx.suspend_flag == -1) { //suspend
        ;
    }
    else { // not suspend

#if ASYNC_PIPELINE
        async_heartbeat();
#elif
        heartbeat(-1);
#endif
        printf("not suspend\n");
        printf("ctx.suspend_flag = %d\n", ctx.suspend_flag);
        printf("seq_num = %d\n", seq_num);

        pthread_mutex_unlock(&snapshot_mtx);

        return 0;
    }

#if DEBUG
    CHERI_CAP_PRINT(cap_ptr);
    printf("pthread_mutex_lock, cid: %d\n", cid);
    printf("pthread_getthreadid_np(): %d\n", pthread_getthreadid_np());
    printf("threadid: %d\n", threadid);
#endif

#if DEBUG
    printf("get_thread_snapshot(CAPTURE_SNAPSHOT, threadid, cap_ptr);, cid: %d\n", cid);
    CHERI_CAP_PRINT(ctx.frame.tf_ra);
    CHERI_CAP_PRINT(ctx.frame.tf_sepc);
    printf("pc_addr: %lx\n", pc_addr);
    unsigned long new_addr = ctx.frame.tf_sepc;
    printf("new_addr: %lx\n", new_addr);
    printf("lower_bound: %lx\n", lower_bound);
    printf("upper_bound: %lx\n", upper_bound);
#endif



    int tag_array[REG_NUM];
    memset(tag_array, 0, sizeof(tag_array));
    uintcap_t *ptr = (uintcap_t *)(&ctx.frame.tf_ra);
    for(int i=0;i<REG_NUM;i++) {
        void *__capability elem = (void *__capability)(ptr[i]); // copyoutcap with tag
#if DEBUG
        printf("[%d]", i);
        CHERI_CAP_PRINT(elem);
#endif

        tag_array[i] = cheri_gettag(elem);
    }

    int fd = open("snapshot/context_dump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
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

    int valid_cap_num = get_cap_info(ct->stack, ct->stack_size);
    int dirty_page_num = stack_dirty_page_update(ct);

    int fd3 = open("snapshot/stack_cap_tags.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd3 == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if (write(fd3, (void *)stack_cap_tags_sparse, valid_cap_num*sizeof(int)) == -1) {
        perror("write stack_cap_tags_sparse");
        close(fd3);
        exit(EXIT_FAILURE);
    }
    close(fd3); 

#if DEBUG
    printf("stack_cap_tags end\n");
#endif

    host_cap_file_dump();

    save_fd_list_snapshot();

#if HEAP_SNAPSHOT
    heap_dirty_page_snapshot(cvms[cid].heap, cvms[cid].heap_size);
#endif

    if(is_master & backup_valid_flag) {
#if ASYNC_PIPELINE
        async_master_to_backup(ct, dirty_page_num, valid_cap_num);
#elif
        master_to_backup(ct, dirty_page_num, valid_cap_num);
#endif
    }

#if DEBUG
    //test suspend
    printf("test suspend start\n");
    sleep(5);
    printf("test suspend end\n");
#endif

    get_thread_snapshot(RESUEM_THREAD, threadid, cap_ptr);
    
#if ANALYSE
    gettimeofday(&end, NULL);
    unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));
    //printf("capture snapshot of %d in %f\n", cid, (now - then) / 1000.0);
    global_capture_count++;
    global_capture_time += ((now - then) / 1000.0);
#endif

    pthread_mutex_unlock(&snapshot_mtx);

    return 0;
}

void print_snapshot_statistics() {
    pthread_mutex_lock(&snapshot_mtx);
    printf("seq_num: %d\n", seq_num);
    printf("capture count: %d\n", global_capture_count);
    printf("capture time: %lfs\n", global_capture_time);
    printf("average capture time: %lfs\n", global_capture_time/global_capture_count);
    pthread_mutex_unlock(&snapshot_mtx);
}







