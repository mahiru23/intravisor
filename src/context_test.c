#include "monitor.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sys/snapshot.h>

void *__capability sealcap;

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
    int cid = 16; // get or calculate
    struct c_thread *ct = cvms[cid].threads;

    while(1) {
        // get info
        sleep(5);
        printf("cvm_dumping 1 ---------------------------------------\n");

        cvm_dumping(cid);

        printf("cvm_dumping 2 ---------------------------------------\n");
    }
}

void *__capability invalid_to_valid(void *__capability elem, void *__capability valid_cap) {

    /*printf("flag 1:  ");
    CHERI_CAP_PRINT(elem);*/

    int ptr_type = 0; //ddc: 0 , pcc: 1
    if((cheri_getperm(elem) & CHERI_PERM_EXECUTE) != 0) {
        printf("pcc\n");
        ptr_type = 1;
    }

    if(cheri_getbase(elem) != 0) {
        CHERI_CAP_PRINT(elem);
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

    /*printf("flag 2:  ");
    CHERI_CAP_PRINT(valid_cap);*/
    valid_cap = cheri_setoffset(valid_cap, cheri_getoffset(elem));
    /*printf("flag 3:  ");
    CHERI_CAP_PRINT(valid_cap);*/
    if(cheri_getoffset(elem) == 0x4c22) {
        CHERI_CAP_PRINT(elem);
        printf("ra!!!!!\n\n\n\n\n ");
        //return valid_cap;
    }

    valid_cap = cheri_setflags(valid_cap, cheri_getflags(elem));

    if(cheri_getsealed(elem)) {
        CHERI_CAP_PRINT(elem);
        if(cheri_gettype(elem) == 0xfffffffffffffffe) {
            printf("cheri_sealentry :  \n\n\n\n\n\n");

            valid_cap = cheri_sealentry(valid_cap);
            
        }
        else {
            valid_cap = cheri_seal(valid_cap, sealcap);
        }
            

        printf("cheri_getsealed :  ");
        CHERI_CAP_PRINT(valid_cap);
    }

    //CHERI_CAP_PRINT(valid_cap);
    return valid_cap;
}

void set_cap_info(void *stack, size_t size) {
    //void **stack_ptr = (void **)stack;
    uintcap_t *stack_ptr = (uintcap_t *)(stack);

    //unsigned long *__capability ptr = (unsigned long *__capability)(stack_ptr);
    uintcap_t *ptr = (uintcap_t *)(stack);

    printf("size: %d\n", size);
    printf("sizeof(uintcap_t *): %d\n", sizeof(uintcap_t *));
    int nums = size / sizeof(uintcap_t *);
    printf("nums: %d\n", nums);

    int sum_cap = 0;
    for (size_t i = 0; i < size / (sizeof(uintcap_t *)*2); ++i) {
        if (stack_cap_tags[i] == 1) {
            //printf("i: %d\n", i);
            unsigned long here_pos = (unsigned long)stack + i*sizeof(void *)*2;
            //if(0x43fffb000<= here_pos&& here_pos<= 0x43fffd000)
                //printf("here_pos: %lx\n", here_pos);

            void * __capability valid_cap;
            valid_cap = invalid_to_valid((void *__capability)(stack_ptr[i]), valid_cap);
            ptr[i] = valid_cap;

            /*printf("flag 3:  ");
            CHERI_CAP_PRINT(valid_cap); 
            CHERI_CAP_PRINT(ptr[i]); */

            sum_cap++;

            //if(0x43fffb000<= here_pos&& here_pos<= 0x43fffd000) {
            /*printf("flag 4:  ");
            CHERI_CAP_PRINT((void *__capability)(stack_ptr[i])); */
        }
    }
    printf("sum_cap: %d\n", sum_cap);
}

void thread_resume(void *argv) {

    pthread_detach(pthread_self());
    int cid = 16; // get or calculate
    struct c_thread *ct = cvms[cid].threads;

    pid_t pid = getpid();


    void * __capability cap_ptr;
    
    void * __capability stack_temp_cap;
    void * __capability stack_cap_ptr;


    //int cid = 16;
    struct thread_snapshot ctx;

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

        valid_cap = cheri_setflags(valid_cap, cheri_getflags(elem));


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

    //get_thread_snapshot(-1, threadid, cap_ptr);

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

    int fd3 = open("stack_cap_tags.bin", O_RDWR);
    if (fd3 == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    if (read(fd3, stack_cap_tags, sizeof(stack_cap_tags)) == -1) {
        perror("write");
        close(fd3);
        exit(EXIT_FAILURE);
    }


    set_cap_info(ct->stack, ct->stack_size);

    resume_from_snapshot(pid, threadid, cap_ptr);

    printf("resume_from_snapshot over\n");


    //sleep(3);

    //get_thread_snapshot(-2, threadid, cap_ptr);

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
	ret = pthread_create(&timerid, NULL, (void *)thread_resume, NULL); 

	if(ret != 0)
	{
		printf("create AppProcessTimer failed!ret=%d err=%s\n", ret, strerror(ret));
	}
}




