#include "monitor.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <sys/snapshot.h>

void thread_get_context(void *argv) {

    pthread_detach(pthread_self());
    int cid = 16; // get or calculate
    struct c_thread *ct = cvms[cid].threads;
    
    while(1) {
        // get info
        sleep(20);
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

// single thread
void context_test() {
	int ret = -1;
	pthread_t timerid;
	ret = pthread_create(&timerid, NULL, (void *)thread_get_context, NULL); 
	if(ret != 0)
	{
		printf("create AppProcessTimer failed!ret=%d err=%s\n", ret, strerror(ret));
	}
}




