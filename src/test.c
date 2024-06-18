
#include "monitor.h"


#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
//#include <sys/proc.h>
//#include <machine/pcb.h>

//#define STACK_SIZE 8192
//#define _GNU_SOURCE

#include <unistd.h>
#include <pthread.h>
//#include <sys/sysmacros.h>
#include <sys/types.h>

#include <sys/malloc.h>
#include <sys/vmmeter.h>
#include <sys/param.h>
#include <sys/systm.h>

//#include <sys/kernel.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>


#include <fcntl.h>
#include <sys/procctl.h>

#include <vm/vm_map.h>
//#include <sys/proc.h>

//#include <machine/pmap.h>

//#define PAGE_SIZE 4096
//#define MEM_SIZE (10 * PAGE_SIZE)

//#define _KERNEL 
//#define LOCK_DEBUG 1
#include <vm/pmap.h>
#include <machine/pmap.h>
#include <sys/proc.h>

#include <ucontext.h>

int test_hostcall() {

    printf("here is test_hostcall\n");
    //printf("1\n");
    usleep(100);

    return 3;
}

void print_context(ucontext_t *context) {
    //printf("Context:\n");
    printf("  gp_sp: 0x%lx\n", context->uc_mcontext.mc_gpregs.gp_sp);
    printf("  gp_t[0]: 0x%lx\n", context->uc_mcontext.mc_gpregs.gp_t[0]);
    printf("  gp_t[5]: 0x%lx\n", context->uc_mcontext.mc_gpregs.gp_t[5]);

#ifdef __CHERI_USER_ABI
    printf(" ?????????????????????????????\n");

#endif
    printf("  mc_capregs: %p\n", context->uc_mcontext.mc_capregs);
}

void get_thread_context() {
    ucontext_t temp;
    getcontext(&temp);
    printf("Context uc_link: %p\n", temp.uc_link);
    printf("Context uc_sigmask: %p\n", temp.uc_sigmask);
    printf("Context uc_mcontext: %p\n", temp.uc_mcontext);
    printf("Context uc_flags: %p\n", temp.uc_flags);
    printf("Context uc_stack: %p\n", temp.uc_stack);

    printf("Context uc_stack.ss_sp: %p\n", temp.uc_stack.ss_sp);
    printf("Context uc_stack.ss_size: %p\n", temp.uc_stack.ss_size);
    printf("Context uc_stack.ss_flags: %p\n", temp.uc_stack.ss_flags);

    printf("(&temp): %p\n", &temp);
    print_context(&temp);
}

void check_dirty_pages(struct c_thread *ct) {
    pthread_t thread_id = ct->tid;
    //pthread_kill(thread_id, SIGSTOP);
    printf("thread_id: %lu\n", thread_id);

    unsigned long start = ct->sbox->cmp_begin;
    unsigned long end = ct->sbox->cmp_end;
    unsigned long MEM_SIZE = end-start;
    int pages = (MEM_SIZE) / PAGE_SIZE;
    printf("pages: %d\n", pages);

    int dirty_pages = 0;
    int dirty_pages2 = 0;
    int dirty_pages3 = 0;
    int dirty_pages4 = 0;

    for (unsigned long addr = start; addr < end; addr += PAGE_SIZE) {
        unsigned char vec;
        if (mincore((void *)addr, PAGE_SIZE, &vec) == -1) {
            perror("mincore");
            exit(1);
        }
        if (vec & MINCORE_MODIFIED) {
            //printf("Page at address %lx is dirty.\n", addr);
            dirty_pages++;
        }

        //vm_page_undirty(m);

        /*if (mincore((void *)addr, PAGE_SIZE, &vec) == -1) {
            perror("mincore");
            exit(1);
        }
        if (vec & MINCORE_MODIFIED) {
            //printf("Page at address %lx is dirty.\n", addr);
            dirty_pages2++;
        }*/
    }
    printf("Total dirty pages: %d\n", dirty_pages);
    unsigned char *vec;
    vec = (unsigned char *)malloc(pages);
    if (vec == NULL) {
        perror("malloc");
    }
    if (mincore(start, MEM_SIZE, vec) == -1) {
        perror("mincore");
        free(vec);
    }
    for (int i = 0; i < pages; i++) {
        if (vec[i] & 1) {
            dirty_pages2++;
        }
    }
    free(vec);
    
    printf("Total dirty pages2: %d\n", dirty_pages2);

    //pthread_kill(thread_id, SIGCONT); // 恢复线程
}



//#define FILE_SIZE 0x40000000  // 文件大小：1GB
//#define PAGE_SIZE 4096         // 页大小：4KB




void mmap_file_test(struct c_thread *ct, int resume_flag) {
    int fd;
    char *addr;
    int dirty_pages = 0;
    unsigned long FILE_SIZE = ct->stack_size;
    int pages = (FILE_SIZE) / PAGE_SIZE;

    addr = mmap(ct->stack, ct->stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        //close(fd);
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    printf("addr: %p\n", addr);
    
    if(resume_flag == 0) {
        int fd2 = open("stack_dump.bin", O_RDWR | O_CREAT | O_TRUNC, 0777);
        if (fd2 == -1) {
            perror("open");
            exit(EXIT_FAILURE);
        }
        if (write(fd2, ct->stack, ct->stack_size) == -1) {
            perror("ct->stack");
            close(fd);
            exit(EXIT_FAILURE);
        }
        printf("create file stack_dump.bin\n");
        close(fd2);
    }
}


