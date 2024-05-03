#include "monitor.h"

#define DEBUG 1




struct s_box get_s_box(int cid) {
    
}

struct c_thread get_c_thread(int cid, int tid) {

}

static const int directory_offset = 4096;
static const int step_by = sizeof(int);
static char *start;
static char *addr;
static char *dir;
static int offset;

void memcpy_and_step_value(const void *val, size_t val_size) {
    memcpy(addr + offset, val, val_size);
    memcpy(dir, &offset, step_by);
    offset += val_size;
    dir += step_by;
}

void memcpy_and_step_addr(const void *val, size_t val_size) {
    memcpy(addr + offset, &val, val_size);
    memcpy(dir, &offset, step_by);
    offset += val_size;
    dir += step_by;
}

/*------------------------------------------------*/


/*void save_all_threads() {
    struct c_thread *ct = cvms[cid].threads;
	for(int i = 0; i < MAX_THREADS; i++) {

        if(ct[i].id == -1) {
            break;
        }

        memcpy_and_step_addr(ct[i].func, sizeof(ct[i].func));
        memcpy_and_step_value(ct[i].cb_in, strlen(ct[i].cb_in) + 1);
        memcpy_and_step_value(ct[i].cb_out, strlen(ct[i].cb_out) + 1);
        memcpy_and_step_addr(ct[i].stack, sizeof(ct[i].stack));
        memcpy_and_step_addr(ct[i].arg, sizeof(ct[i].arg));
        memcpy_and_step_value(&ct[i].stack_size, sizeof(ct[i].stack_size));
        memcpy_and_step_value(&ct[i].id, sizeof(ct[i].id));

        memcpy_and_step_addr(ct[i].c_tp, sizeof(ct[i].c_tp));
        memcpy_and_step_addr(ct[i].m_tp, sizeof(ct[i].m_tp));

        memcpy_and_step_value(&ct[i].argc, sizeof(ct[i].argc));

        for(int j=0; j<ct[i].argc; j++) {
            memcpy_and_step_value(ct[i].argv[j], strlen(ct[i].argv[j]) + 1);
        }



	}
}*/


// TODO: tracing the dirty bit in this function
int get_dirty_page_num2(unsigned long FILE_SIZE, int pages, char *addr) {
    int dirty_pages = 0;
    char *vec = (char *)malloc(pages);
    if (vec == NULL) {
        perror("malloc");
        return -1;
    }
    if (mincore(addr, FILE_SIZE, vec) == -1) {
        perror("mincore");
        free(vec);
        return -1;
    }
    for (int i = 0; i < pages; i++) {
        if (vec[i] & MINCORE_MODIFIED) {
            // TODO: update here
            dirty_pages++;
        }
    }
    printf("Total dirty pages: %d\n", dirty_pages);
    free(vec);
    return dirty_pages;
}


int memory_store(struct c_thread *ct) {
    int fd;
    char *map_addr;
    int dirty_pages = 0;

    unsigned long start = ct->sbox->cmp_begin;
    unsigned long end = ct->sbox->cmp_end;
    unsigned long MEM_SIZE = end-start;
    int pages = (MEM_SIZE) / PAGE_SIZE;


    // create mapped file
    fd = open("mapped_file", O_RDWR | O_CREAT, (mode_t)0600);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // extend file to memory size
    if (lseek(fd, MEM_SIZE - 1, SEEK_SET) == -1) {
        close(fd);
        perror("lseek");
        exit(EXIT_FAILURE);
    }

    if (write(fd, "", 1) == -1) {
        close(fd);
        perror("write");
        exit(EXIT_FAILURE);
    }

    // mapped file to memory
    map_addr = mmap((void *)ct->sbox->cmp_begin, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map_addr == MAP_FAILED) {
        close(fd);
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // whole segment
    memcpy_and_step_value(map_addr, MEM_SIZE);
    
    // close
    if (munmap(map_addr, MEM_SIZE) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }
    close(fd);
    return 0;
}

size_t file_size(struct c_thread *ct) {
    size_t s = directory_offset + sizeof(ucontext_t) + /*(ct->sbox->cmp_end - ct->sbox->cmp_begin) +*/ \
    /*sizeof(struct s_box) * MAX_CVMS + sizeof(timers) + sizeof(debug_calls) + sizeof(print_lock) + \*/
    sizeof(ct->sbox->cid) + sizeof(ct->id) + sizeof(void * __capability)*3 + sizeof(unsigned long)*3;
    /*sizeof(lkl_host_ops) + sizeof(lkl_dev_blk_ops) + sizeof(fd_net_ops);*/

    return s*sizeof(char);
}

int cvm_dumping(struct c_thread *ct, void * __capability pcc, void * __capability ddc, void * __capability ddc2,unsigned long s0,unsigned long ra,unsigned long sp) {
    //printf("cvm_dumping\n");


    int file_len = file_size(ct);
    start = (char*)malloc(file_len);
    if(start == NULL) {
        perror("malloc error");
        exit(EXIT_FAILURE);
    }
    addr = start + directory_offset;
    dir = start;
    offset = 0;
    /*stop the thread*/
    /*only stall at first stage in pipeline*/
    /*int ret = pthread_suspend(pthread_t target_thread);
	if(ret != 0) {
		perror("pthread_suspend error");
		printf("ret = %d\n", ret);
		return -1;
	}*/

    #if DEBUG
            printf("cvm_dumping\n");
    #endif

    /*encode context & memory*/
    /*first part: directory; second part: data(context-memory-intra_cvms_struct)*/
    /*may duplicated, simple & acceptable*/
    memcpy_and_step_value(&pcc, sizeof(pcc));
    memcpy_and_step_value(&ddc, sizeof(ddc));
    memcpy_and_step_value(&ddc2, sizeof(ddc2));
    memcpy_and_step_value(&s0, sizeof(s0));
    memcpy_and_step_value(&ra, sizeof(ra));
    memcpy_and_step_value(&sp, sizeof(sp));

    /*resume flag*/
    memcpy_and_step_value(&ct->sbox->cid, sizeof(ct->sbox->cid));
    memcpy_and_step_value(&ct->id, sizeof(ct->id));

    #if DEBUG
            printf("resume flag end\n");
    #endif

    /*global variable*/
    /*memcpy_and_step_value(&cvms, sizeof(struct s_box) * MAX_CVMS);
    memcpy_and_step_value(&timers, sizeof(timers));
    memcpy_and_step_value(&debug_calls, sizeof(debug_calls));
    memcpy_and_step_value(&print_lock, sizeof(print_lock));*/

    #if DEBUG
            printf("global variable end\n");
    #endif

    /*memcpy_and_step_value(&lkl_host_ops, sizeof(lkl_host_ops));
    memcpy_and_step_value(&lkl_dev_blk_ops, sizeof(lkl_dev_blk_ops));
    memcpy_and_step_value(&fd_net_ops, sizeof(fd_net_ops));*/

    /*get register*/
    /*read from sys/(riscv|arm)/include/ucontext.h*/
    /*e.g. context->uc_mcontext.mc_gpregs.gp_sp*/
    ucontext_t thread_context;
    getcontext(&thread_context);
    memcpy_and_step_value(&thread_context, sizeof(thread_context));

    #if DEBUG
        void *__capability pcc_cap = cheri_getpcc();
        printf("  gp_ra: 0x%p\n", thread_context.uc_mcontext.mc_gpregs.gp_ra);
        printf("  gp_sepc: 0x%p\n", thread_context.uc_mcontext.mc_gpregs.gp_sepc);
        printf("pcc_cap:  ");
        CHERI_CAP_PRINT(pcc_cap);
    #endif

    int fd = open("context_dump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if (write(fd, start, file_len) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }

    #if DEBUG
            printf("thread_context end\n");
    #endif

    #if DEBUG
            printf("mem flag\n");
            printf("mem len: %p\n", ct->sbox->cmp_end - ct->sbox->cmp_begin);
            printf("mem base: %p\n", ct->sbox->cmp_begin);

            printf("stack: %p\n", ct->stack);
            printf("stack_size: %p\n", ct->stack_size);
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




    /*if (write(fd, ct->sbox->cmp_begin, ct->sbox->cmp_end - ct->sbox->cmp_begin) == -1) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }*/




    /*if(resume_flag == 1) {
        resume_flag = 0;
        printf("resume_flag == 1 \n");
        return 1;
    }*/



    /*get memory*/
    //memory_store(ct);


    //memcpy_and_step_value(ct->sbox->cmp_begin, ct->sbox->cmp_begin - ct->sbox->cmp_end);
    #if DEBUG
            printf("get memory end\n");
    #endif



    /*data for build cvm*/
    /*TODO: here only use thread[0]*/



    /*#if riscv
        
    #if DEBUG
            printf("we have __cap_relocs, it is a purecap binary\n");
    #endif

    #if arm
        
    #if DEBUG
            printf("we have __cap_relocs, it is a purecap binary\n");
    #endif*/

    /*get cVM data structure*/
    /*check share point to avoid shallow copy*/
    /*cvms[cid]
    struct c_thread *ct = cvms[cid].threads;
	for(int i = 0; i < MAX_THREADS; i++) {
		//ct[i].id = -1;
		//ct[i].sbox = &cvms[cid];
	}*/

    /*save as binary file*/

    close(fd); 

    #if DEBUG
            printf("save as binary file end\n");
    #endif

    /*destory the resource(if necessary?)*/
    /*important to avoid memory leak*/
    exit(-1);
}


/*void read_context_from_fd(int fd, ucontext_t *thread_context, size_t len) {
    size_t bytes_read = read(fd, thread_context, len);
    if (bytes_read != len) {
        perror("read");
        exit(EXIT_FAILURE);
    }
}*/

long remaining_file_size(int fd) {
    // 获取当前文件指针的位置
    off_t current_pos = lseek(fd, 0, SEEK_CUR);
    if (current_pos == -1) {
        perror("Failed to get current file position");
        return -1;
    }

    // 将文件指针移到文件尾部
    off_t end_pos = lseek(fd, 0, SEEK_END);
    if (end_pos == -1) {
        perror("Failed to seek to end of file");
        return -1;
    }

    // 计算剩余长度
    long remaining_size = end_pos - current_pos;

    // 将文件指针移回原来的位置
    if (lseek(fd, current_pos, SEEK_SET) == -1) {
        perror("Failed to seek back to original position");
        return -1;
    }

    return remaining_size;
}

void read_context_from_fd(int fd, void *context, size_t len) {
    printf("remain len: %p\n", remaining_file_size(fd));
    size_t bytes_read = read(fd, context, len);
    if (bytes_read != len) {
        perror("read");
        exit(EXIT_FAILURE);
    }
}

void read_memory_from_fd(struct c_thread *ct, unsigned long v1, unsigned long v2, unsigned long v3) {
            printf("stack: %p\n", ct->stack);
            printf("stack_size: %p\n", ct->stack_size);

    int fd = open("stack_dump.bin", O_RDWR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    /*size_t bytes_read = read(fd, ct->stack, ct->stack_size);
    if (bytes_read != ct->stack_size) {
        perror("read");
        exit(EXIT_FAILURE);
    }*/

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

    //test_resume_jump(ct->sbox->box_caps.sealed_ret_from_mon, ct->sbox->box_caps.sealed_datacap, ct->sbox->box_caps.dcap, v1, v2, v3);
	//__asm__ __volatile__("cmove ct0, %0;" :: "C"(ct->sbox->box_caps.sealed_ret_from_mon) : "memory");
	//__asm__ __volatile__("cmove ct1, %0;" :: "C"(ct->sbox->box_caps.sealed_datacap) : "memory");
	//__asm__ __volatile__("cmove ct2, %0;" :: "C"(ct->sbox->box_caps.dcap) : "memory");
    __asm__ __volatile__("cmove ctp, cs9;" ::  : "memory");
	__asm__ __volatile__("mv ra, s7;" ::  : "memory");
	__asm__ __volatile__("mv sp, s8;" ::  : "memory");
	__asm__ __volatile__("mv s0, s6;" ::  : "memory");
	__asm__ __volatile__("cspecialw	ddc, cs5;" ::  : "memory");
	__asm__ __volatile__("CInvoke cs3, cs4;" ::  : "memory");


    printf("addr sp: %p\n", addr[0]);
    printf("sp+16: %p\n", addr[16]);
    printf("sp+32: %p\n", addr[32]);
    printf("sp+48: %p\n", addr[48]);
    printf("sp+64: %p\n", addr[64]);

    /*printf("remain len: %p\n", remaining_file_size(fd));
    printf("offset: %p\n", offset);
    printf("len: %p\n", len);
    int pages = (len) / PAGE_SIZE;

    off_t map_offset = lseek(fd, 0, SEEK_CUR);

    printf("map_offset: %p\n", map_offset);

    unsigned long newsp = 0x3fffbf30;*/

    /*char* newaddr = (char*)malloc(len);
    size_t bytes_read = read(fd, newaddr, len);
    if (bytes_read != len) {
        perror("read");
        exit(EXIT_FAILURE);
    }*/

    /*char *addr = mmap((void *)offset, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        printf("???????????????\n");
        close(fd);
        perror("mmap");
        exit(EXIT_FAILURE);
    }*/

    /*size_t bytes_read = read(fd, offset, len);
    if (bytes_read != len) {
        perror("read");
        exit(EXIT_FAILURE);
    }*/

    /*addr = mmap((void *)offset, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, map_offset);
    if (addr == MAP_FAILED) {
        printf("???????????????\n");
        close(fd);
        perror("mmap");
        exit(EXIT_FAILURE);
    }*/

    /*printf("sp: %p\n", offset[newsp]);
    printf("sp+16: %p\n", offset[newsp+16]);
    printf("sp+32: %p\n", offset[newsp+32]);
    printf("sp+48: %p\n", offset[newsp+48]);
    printf("sp+64: %p\n", offset[newsp+64]);*/

    /*printf("addr sp: %p\n", addr[newsp]);
    printf("sp+16: %p\n", addr[newsp+16]);
    printf("sp+32: %p\n", addr[newsp+32]);
    printf("sp+48: %p\n", addr[newsp+48]);
    printf("sp+64: %p\n", addr[newsp+64]);*/

    // 告诉系统尽快加载内存
    /*if (madvise(addr, len, MADV_WILLNEED) == -1) {
        perror("madvise");
        exit(EXIT_FAILURE);
    }

    char *c;
    for (int i = 0; i < pages; ++i) {
        c = addr[i * PAGE_SIZE];
    }*/



    /*get_dirty_page_num(len, pages, addr);
    if (msync(addr, len, MS_SYNC) == -1) {
        perror("msync");
        exit(EXIT_FAILURE);
    }
    get_dirty_page_num(len, pages, addr);*/

    /*char *base = (char *)mmap(offset, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, map_offset);
    if (base == MAP_FAILED) {
        perror("Failed to mmap memory");
        exit(EXIT_FAILURE);
    }*/


    /*size_t bytes_read = read(fd, base, len);
    if (bytes_read != len) {
        perror("read");
        exit(EXIT_FAILURE);
    }*/

    // close
    /*if (munmap(base, len) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }*/
}


struct resume_temp_struct {
    void * __capability pcc; 
    void * __capability ddc; 
    void * __capability ddc2;
    unsigned long s0;
    unsigned long ra;
    unsigned long sp;
};

int resume_thread_init(struct resume_temp_struct *resume_temp) {
    printf("sp resume_thread_init: %p\n", getSP());
    printf("resume_thread_init\n");
    /*if(setcontext(new_context) == -1) {
        perror("setcontext");
        printf("setcontext fail");
        exit(EXIT_FAILURE);
    }*/
    CHERI_CAP_PRINT(resume_temp->pcc);
    CHERI_CAP_PRINT(resume_temp->ddc);
    CHERI_CAP_PRINT(resume_temp->ddc2);

    //test_resume_jump(resume_temp->pcc, resume_temp->ddc, resume_temp->ddc2, resume_temp->s0, resume_temp->ra, resume_temp->sp);

    printf("resumetest\n");
    //test_resume_jump(void * __capability pcc, void * __capability ddc)

    //extern void resumetest();
    //resumetest();

	return 0;
}


int cvm_resume(struct c_thread *ct, unsigned long *v1, unsigned long *v2, unsigned long *v3) {
    int fd;
   #if DEBUG
            printf("enter\n");
    #endif
    // create mapped file
    fd = open("context_dump.bin", O_RDWR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    #if DEBUG
            printf("cvm_resume\n");
    #endif

    char* dir_point = (char *)malloc(directory_offset);
    if (dir_point == NULL) {
        perror("malloc");
        return -1;
    }
    if (read(fd, dir_point, directory_offset) != directory_offset) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    unsigned long cid;
    int tid;

    /*void * __capability pcc; 
    void * __capability ddc; 
    void * __capability ddc2;
    unsigned long s0;
    unsigned long ra;
    unsigned long sp;*/

    struct resume_temp_struct resume_temp;


    

    read_context_from_fd(fd, &resume_temp.pcc, sizeof(resume_temp.pcc));
    read_context_from_fd(fd, &resume_temp.ddc, sizeof(resume_temp.ddc));
    read_context_from_fd(fd, &resume_temp.ddc2, sizeof(resume_temp.ddc2));
    read_context_from_fd(fd, &resume_temp.s0, sizeof(resume_temp.s0));
    read_context_from_fd(fd, &resume_temp.ra, sizeof(resume_temp.ra));
    read_context_from_fd(fd, &resume_temp.sp, sizeof(resume_temp.sp));

    *v1 = resume_temp.s0;
    *v2 = resume_temp.ra;
    *v3 = resume_temp.sp;

    resume_temp.pcc = ct->sbox->box_caps.sealed_ret_from_mon;
    resume_temp.ddc = ct->sbox->box_caps.sealed_datacap;
    resume_temp.ddc2 = ct->sbox->box_caps.dcap;

    CHERI_CAP_PRINT(resume_temp.pcc);
    CHERI_CAP_PRINT(resume_temp.ddc);
    CHERI_CAP_PRINT(resume_temp.ddc2);

    #if DEBUG
            printf("id flag\n");
    #endif

    read_context_from_fd(fd, &cid, sizeof(cid));
    read_context_from_fd(fd, &tid, sizeof(tid));

    #if DEBUG
            printf("global flag\n");
    #endif


    /*read_context_from_fd(fd, &cvms, sizeof(struct s_box) * MAX_CVMS);
    read_context_from_fd(fd, &timers, sizeof(timers));
    read_context_from_fd(fd, &debug_calls, sizeof(debug_calls));
    read_context_from_fd(fd, &print_lock, sizeof(print_lock));*/

    /*read_context_from_fd(fd, &lkl_host_ops, sizeof(lkl_host_ops));
    read_context_from_fd(fd, &lkl_dev_blk_ops, sizeof(lkl_dev_blk_ops));
    read_context_from_fd(fd, &fd_net_ops, sizeof(fd_net_ops));*/

    #if DEBUG
            printf("context flag\n");
    #endif

    ucontext_t new_context;
    read_context_from_fd(fd, &new_context, sizeof(ucontext_t));

    #if DEBUG
            printf("mem flag\n");
            printf("mem len: %p\n", cvms[cid].top - cvms[cid].base);
            printf("mem base: %p\n", cvms[cid].base);

            printf("sizeof(int): %d\n", sizeof(int));
            printf("sizeof(unsigned long): %d\n", sizeof(unsigned long));


    #endif

    #if DEBUG
        void *__capability pcc_cap = cheri_getpcc();
        printf("  gp_ra: 0x%p\n", new_context.uc_mcontext.mc_gpregs.gp_ra);
        printf("  gp_sepc: 0x%p\n", new_context.uc_mcontext.mc_gpregs.gp_sepc);
        printf("pcc_cap:  ");
        CHERI_CAP_PRINT(pcc_cap);
    #endif

    //mem: base+len
    

    // create new thread, swap the context in this thread
    // keep the main intravisor thread deamon? i'm not sure

    #if DEBUG
            printf("pthread_create flag\n");
    #endif

    pthread_t temp_tid;
    void *cret;

    /*char* offset = cvms[cid].base;
    unsigned long newsp = 0x3fffbf30;
    printf("sp: %p\n", offset[newsp]);
    printf("sp+16: %p\n", offset[newsp+16]);
    printf("sp+32: %p\n", offset[newsp+32]);
    printf("sp+48: %p\n", offset[newsp+48]);
    printf("sp+64: %p\n", offset[newsp+64]);

    printf("sp resume: %p\n", getSP());*/

    //pthread_create(&temp_tid, NULL, resume_thread_init, &new_context);
    /*pthread_create(&temp_tid, NULL, resume_thread_init, &resume_temp);

    

    #if DEBUG
            printf("pthread_join flag\n");
    #endif

    while(1) {
        sleep(1);
    }

    pthread_join(tid, &cret);*/

    return 0;

}












