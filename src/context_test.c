#include "monitor.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sys/snapshot.h>

// 获取当前线程的栈位置和大小
void print_stack_info() {
    pthread_t self = pthread_self();
    pthread_attr_t attr;
    size_t stack_size;
    void* stack_addr;

    // 初始化线程属性
    pthread_attr_init(&attr);

    // 获取线程属性
    pthread_attr_get_np(self, &attr);

    // 获取栈大小
    pthread_attr_getstacksize(&attr, &stack_size);

    // 获取栈地址
    pthread_attr_getstack(&attr, &stack_addr, &stack_size);

    // 打印栈信息
    printf("Stack address: %p\n", stack_addr);
    printf("Stack size: %zu bytes\n", stack_size);

    // 销毁线程属性
    pthread_attr_destroy(&attr);
}


void thread_get_context(void *argv) {

    pthread_detach(pthread_self());
    int cid = 16; // get or calculate
    struct c_thread *ct = cvms[cid].threads;

    print_stack_info();
    
    while(1) {
        // get info
        sleep(5);
        printf("---------------------------------------\n");

        cvm_dumping(cid);





        CHERI_CAP_PRINT(ct->c_tp);
        CHERI_CAP_PRINT(ct->m_tp);
        void * ptr = cheri_getaddress(ct->c_tp);
        printf("ptr: %p\n", ptr);
        printf("ptr2: %p\n", cheri_getaddress(ct->m_tp));
        printf("(__cheri_fromcap void *)(ct->c_tp): %p\n", (__cheri_fromcap void *)(ct->c_tp));
        printf("(__cheri_fromcap void *)(ct->m_tp): %p\n", (__cheri_fromcap void *)(ct->m_tp));



        // extra syscall get context
        struct thread_snapshot ctx;
        pid_t pid = getpid();
        pthread_t tid = pthread_self();

        //lwpid_t threadid = pthread_getthreadid_np();
        printf("threadid: %d\n", threadid);
        printf("SYS_get_thread_snapshot: %d\n", SYS_get_thread_snapshot);

        void * __capability cap_ptr = cheri_ptrperm(&ctx, 1000000000, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL | CHERI_PERMS_HWALL);
        CHERI_CAP_PRINT(cap_ptr);

    	/*void *__capability ccap = datacap_create((void *)(0), (void *) (0xffffffffffffffff), true);
        ccap = cheri_setaddress(ccap, (unsigned long) (&ctx));
        CHERI_CAP_PRINT(ccap);*/


        //syscall(SYS_get_thread_snapshot, pid, tid, threadid, &ctx);
        int ret = get_thread_snapshot(pid, threadid, cap_ptr);
        printf("%d\n", sizeof(ctx));
        printf("%d\n", ret);
        //get_thread_snapshot(1);


    //void *ptr = cheri_address_get(ctx.frame.tf_sepc);
    //uintcap_t read_only_cap = cheri_perms_and(cap_ptr, CHERI_PERM_LOAD);
    

        /*printf("ctx.frame.tf_sp: %p\n", &ctx.frame.tf_sp);
        printf("ctx.frame.tf_ra: %p\n", &ctx.frame.tf_ra);
        printf("ctx.frame.tf_ddc: %p\n", &ctx.frame.tf_ddc);
        printf("ctx.frame.tf_sepc: %p\n", &ctx.frame.tf_sepc);
        printf("ctx.frame.tf_sepc: %p\n", ctx.frame.tf_sepc);*/



        CHERI_CAP_PRINT(ctx.frame.tf_sepc);
        CHERI_CAP_PRINT(ctx.frame.tf_ra);
        CHERI_CAP_PRINT(ctx.frame.tf_sp);
        //unsigned long value = *(unsigned long *)(ctx.frame.tf_sepc); 
        //printf("ctx.frame.tf_sepc: %p\n", value);







        printf("---------------------------------------\n");
    }


    
}



void thread_get_context2(void *argv) {

    pthread_detach(pthread_self());
    int cid = 16; // get or calculate
    struct c_thread *ct = cvms[cid].threads;

    pid_t pid = getpid();


    void * __capability cap_ptr;
    
    void * __capability stack_temp_cap;
    void * __capability stack_cap_ptr;


    //int cid = 16;
    struct thread_snapshot ctx;

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
        void *__capability elem = (void *__capability)(ptr[i]);
        printf("[%d] origin tag: %d\n", i, tag_array[i]);
        
        CHERI_CAP_PRINT(elem);

        if(tag_array[i] == 0) {
            continue;
        }

        int ptr_type = 0;//ddc: 0 , pcc: 1
        if((cheri_getperm(elem)&CHERI_PERM_EXECUTE )!= 0) {
            printf("pcc\n");
            ptr_type = 1;
        }

        //void * new_ptrx = (void *)cheri_getbase(elem);

        //void *__capability new_temp_cap;
        //CHERI_CAP_PRINT_KERN(pcc_temp);

        /*void *__capability pcc_temp = cheri_getpcc();
        pcc_temp = cheri_setaddress(pcc_temp, cheri_getbase(elem));
        CHERI_CAP_PRINT(pcc_temp);*/

        //CHERI_PERMS_HWALL
        void *__capability valid_cap;// = cheri_ptrperm((void *)cheri_getaddress(elem), cheri_getlength(elem), CHERI_PERMS_HWALL|CHERI_PERMS_SWALL);

        

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
                //valid_cap = cheri_codeptrperm(cheri_getbase(elem), cheri_getlength(elem), cheri_getperm(elem));
            }
            else {
                valid_cap = cheri_getpcc();
                valid_cap = cheri_setoffset(valid_cap, 0);
                valid_cap = cheri_codeptrperm(cheri_getbase(elem), cheri_getlength(elem), cheri_getperm(elem));
            }
        }
        CHERI_CAP_PRINT(valid_cap);
        valid_cap = cheri_setoffset(valid_cap, cheri_getoffset(elem));


        /*if(i==31) {
            valid_cap = cheri_setoffset(valid_cap, cheri_getoffset(elem));
        }
        else {
            valid_cap = cheri_setoffset(valid_cap, cheri_getoffset(elem));
        }*/
        
        if(cheri_getsealed(elem))
            valid_cap = cheri_seal(valid_cap, sealcap);
        ptr[i] = valid_cap;
        CHERI_CAP_PRINT(valid_cap);
        //printf("%p\n", elem);
    }

    /*void * __capability ccap;
    ccap = pure_codecap_create((void *) ct[0].sbox->cmp_begin, (void *) ct[0].sbox->cmp_end, cvms[cid].clean_room);
    ccap = cheri_setaddress(ccap, (unsigned long)(ctx.frame.tf_sepc));

    CHERI_CAP_PRINT(ccap);

    ctx.frame.tf_sepc = ccap;*/
    CHERI_CAP_PRINT(ctx.frame.tf_sepc);


    sleep(5);

    get_thread_snapshot(-1, threadid, cap_ptr);

    host_cap_file_resume();

    cap_ptr = cheri_ptrperm(&ctx, 1000000000, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE \
    | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP | CHERI_PERM_CCALL | CHERI_PERMS_HWALL);
    #if DEBUG
            CHERI_CAP_PRINT(cap_ptr);
    #endif


    int fd_stack = open("stack_dump.bin", O_RDWR);
    if (fd_stack == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    char *addr = mmap(ct->stack, ct->stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd_stack, 0);
    if (addr == MAP_FAILED) {
        printf("???????????????\n");
        close(fd_stack);
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    resume_from_snapshot(pid, threadid, cap_ptr);


    sleep(3);

    get_thread_snapshot(-2, threadid, cap_ptr);

    while(1) {
        sleep(1);
    }
    
}



// single thread
void context_test(int no) {
    print_stack_info();
	int ret = -1;
	pthread_t timerid;
    if(no == 1)
	ret = pthread_create(&timerid, NULL, (void *)thread_get_context, NULL); 
    if(no == 2)
	ret = pthread_create(&timerid, NULL, (void *)thread_get_context2, NULL); 

	if(ret != 0)
	{
		printf("create AppProcessTimer failed!ret=%d err=%s\n", ret, strerror(ret));
	}
}




