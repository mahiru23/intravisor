#include "monitor.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/snapshot.h>

void thread_get_context(void *argv) {

    pthread_detach(pthread_self());
    int cid = 16; // get or calculate
    struct c_thread *ct = cvms[cid].threads;
    
    while(1) {
        // get info
        sleep(3);
        printf("---------------------------------------");
        CHERI_CAP_PRINT(ct->c_tp);
        CHERI_CAP_PRINT(ct->m_tp);

        // extra syscall get context
        struct thread_snapshot ctx;
        pid_t pid = getpid();
        pthread_t tid = pthread_self();

        syscall(SYS_get_thread_snapshot, pid, tid, ctx);

        printf("ctx.frame.tf_ddc: %p\n", ctx.frame.tf_ddc);







        printf("---------------------------------------");
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




