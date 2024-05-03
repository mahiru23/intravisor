
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


/*int get_dirty_page() {
    void *mem;
    unsigned char *vec;
    int i, pages;

    // 分配内存
    mem = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // 计算页数
    pages = MEM_SIZE / PAGE_SIZE;

    // 分配页状态数组
    vec = (unsigned char *)malloc(pages);
    if (vec == NULL) {
        perror("malloc");
        munmap(mem, MEM_SIZE);
        exit(EXIT_FAILURE);
    }

    // 获取内存中的脏页信息
    if (mincore(mem, MEM_SIZE, vec) == -1) {
        perror("mincore");
        free(vec);
        munmap(mem, MEM_SIZE);
        exit(EXIT_FAILURE);
    }

    // 统计脏页数量
    int dirty_pages = 0;
    for (i = 0; i < pages; i++) {
        if (vec[i] & 1) {
            dirty_pages++;
        }
    }

    printf("Number of dirty pages: %d\n", dirty_pages);

    // 释放资源
    free(vec);
    munmap(mem, MEM_SIZE);
}*/

/*void count_dirty_pages()
{
    int i;
    int dirty_pages = 0;

    for (i = 0; i < vm_page_count_severe; i++) {
        struct vm_page *m = &vm_page_array[i];

        if (m->valid && (m->dirty || (m->flags & PG_WRITEABLE))) {
            dirty_pages++;
        }
    }

    printf("Total dirty pages: %d\n", dirty_pages);
}
*/

// 通过虚拟地址获取对应的 vm_page_t 结构体
/*vm_page_t get_vm_page_t(vm_offset_t vaddr) {
    vm_page_t m;

    // 使用 pmap_extract 函数获取虚拟地址对应的物理地址
    pmap_t pmap = kernel_pmap;
    vm_paddr_t vpaddr = pmap_extract(pmap, vaddr);

    // 通过物理地址找到相应的 vm_page_t 结构体
    m = PHYS_TO_VM_PAGE(vpaddr);
    return m;
}*/


/*vm_page_t
get_vm_page_from_vaddr(vm_offset_t vaddr)
{
    struct pmap *pmap;
    vm_page_t m;

    struct proc *p = pfind(getpid());


    pmap = vmspace_pmap(p->p_vmspace);

    pmap_extract_and_hold(pmap, vaddr);

    if (pmap != NULL && (m = pmap_extract_and_hold(pmap, vaddr, VM_PROT_READ)) != NULL) {
        return m;
    }

    return NULL;
}*/

void print_context(ucontext_t *context) {
    //printf("Context:\n");
    printf("  gp_sp: 0x%lx\n", context->uc_mcontext.mc_gpregs.gp_sp);
    printf("  gp_t[0]: 0x%lx\n", context->uc_mcontext.mc_gpregs.gp_t[0]);
    printf("  gp_t[5]: 0x%lx\n", context->uc_mcontext.mc_gpregs.gp_t[5]);

#ifdef __CHERI_USER_ABI
    printf(" ?????????????????????????????\n");

#endif
    printf("  mc_capregs: %p\n", context->uc_mcontext.mc_capregs);


    //CHERI_CAP_PRINT(context->uc_mcontext.mc_capregs.cp_sp);
    //printf("  cp_ct[5]: 0x%lx\n", context->uc_mcontext.mc_capregs.cp_csp);
    // Add more fields as needed depending on your requirements
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

    //get_thread_context();

    printf("(ct): %p\n", ct);
    printf("(ct->sbox): %p\n", ct->sbox);

    printf("&(cmvs[10]): %p\n", &(cvms[10]));
    printf("&(cmvs[11]): %p\n", &(cvms[11]));

    printf("&(ct->s_box->threads[0]): %p\n", &(ct->sbox->threads[0]));
    printf("&(ct->s_box->threads[1]): %p\n", &(ct->sbox->threads[1]));

    

    printf("csizeof1: %d\n", sizeof(ct->arg));
    printf("sizeof: %d\n", sizeof(ct->func));



    printf("ct->sbox->cmp_begin: 0x%lx\n", ct->sbox->cmp_begin);
    printf("ct->sbox->cmp_end: 0x%lx\n", ct->sbox->cmp_end);

    

    pthread_t thread_id = ct->tid;

    
    //pthread_kill(thread_id, SIGSTOP); // 暂停线程以确保一致性
    printf("thread_id: %lu\n", thread_id);

    unsigned long start = ct->sbox->cmp_begin;
    unsigned long end = ct->sbox->cmp_end;
    unsigned long MEM_SIZE = end-start;
    int pages = (MEM_SIZE) / PAGE_SIZE;
    printf("pages: %d\n", pages);


    
    // 遍历页面并检查脏位
    int dirty_pages = 0;
    int dirty_pages2 = 0;
    int dirty_pages3 = 0;
    int dirty_pages4 = 0;

    for (unsigned long addr = start; addr < end; addr += PAGE_SIZE) {
        unsigned char vec;
        //vm_offset_t vaddr = addr; // 虚拟地址
        // 获取对应的 vm_page_t 结构体
        //vm_page_t m = get_vm_page_t(vaddr);

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


    // 分配页状态数组
    unsigned char *vec;
    vec = (unsigned char *)malloc(pages);
    if (vec == NULL) {
        perror("malloc");
    }

    // 获取内存中的脏页信息
    if (mincore(start, MEM_SIZE, vec) == -1) {
        perror("mincore");
        free(vec);
    }

    // 统计脏页数量
    for (int i = 0; i < pages; i++) {
        if (vec[i] & 1) {
            dirty_pages2++;
        }
    }

    // 释放资源
    free(vec);


    
    printf("Total dirty pages2: %d\n", dirty_pages2);

    //pthread_kill(thread_id, SIGCONT); // 恢复线程
}



//#define FILE_SIZE 0x40000000  // 文件大小：1GB
//#define PAGE_SIZE 4096         // 页大小：4KB

int get_dirty_page_num(unsigned long FILE_SIZE, int pages, char *addr) {
    int dirty_pages = 0;

    //get_thread_context();
    //get_thread_context();

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
            dirty_pages++;
        }
    }
    printf("Total dirty pages: %d\n", dirty_pages);
    free(vec);
    return dirty_pages;
}

int mmaptest(struct c_thread *ct) {
    int fd;
    char *addr;
    int dirty_pages = 0;

    unsigned long start = ct->sbox->cmp_begin;
    unsigned long end = ct->sbox->cmp_end;
    unsigned long FILE_SIZE = PAGE_SIZE*100;
    int pages = (FILE_SIZE) / PAGE_SIZE;
    printf("FILE_SIZE: %d\n", FILE_SIZE);
    printf("pages: %d\n", pages);
    printf("ct->sbox->cmp_begin: 0x%lx\n", ct->sbox->cmp_begin);
    printf("ct->sbox->cmp_end: 0x%lx\n", ct->sbox->cmp_end);


    // 创建一个文件用于映射
    fd = open("mapped_file", O_RDWR | O_CREAT , (mode_t)0600);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    printf("flag 0\n");

    // 将文件扩展到指定大小
    /*if (lseek(fd, FILE_SIZE - 1, SEEK_SET) == -1) {
        close(fd);
        perror("lseek");
        exit(EXIT_FAILURE);
    }*/

    printf("flag 1\n");

    /*if (write(fd, "", 1) == -1) {
        close(fd);
        perror("write");
        exit(EXIT_FAILURE);
    }*/

    printf("flag 2\n");

    

    ssize_t bytes_written = write(fd, start, FILE_SIZE);
    if (bytes_written == -1) {
        perror("write");
        close(fd);
        return 1;
    }
    close(fd);
    exit(-1);


    // 映射文件到内存
    addr = mmap((void *)ct->sbox->cmp_begin, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    printf("addr: %p\n", addr);
    printf("ct->sbox->cmp_begin: 0x%lx\n", ct->sbox->cmp_begin);


    get_dirty_page_num(FILE_SIZE, pages, addr);


    // 修改一部分内存内容
    /*for (int i = 0; i < pages / 32; ++i) {
        addr[i * PAGE_SIZE] = 'a';
    }*/
    //addr[50000 * PAGE_SIZE + 100] = 'a';

    get_dirty_page_num(FILE_SIZE, pages, addr);

    // 写回脏页
    if (msync(addr, FILE_SIZE, MS_SYNC) == -1) {
        perror("msync");
        exit(EXIT_FAILURE);
    }

    get_dirty_page_num(FILE_SIZE, pages, addr);
    
    // 解除映射并关闭文件
    if (munmap(addr, FILE_SIZE) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }
    close(fd);
    return 0;
}


/*void test_get_thread_info(struct c_thread *ct) {
    // Get stack address from thread attributes
    void* stackAddr;
    size_t stackSize;
    pthread_attr_getstack(&ct->tattr, &stackAddr, &stackSize);
    printf("Stack Address: %p\n", stackAddr);
    printf("Stack Size: %p\n", stackSize);




}*/






