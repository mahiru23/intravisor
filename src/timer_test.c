#include "monitor.h"
#define _GNU_SOURCE
#include <pthread_np.h>

#include <vm/vm_param.h>





int i = 1;

void start_timer(void *argv)
{
	struct itimerval tick;
	timer_para * time_val;

	time_val = (timer_para *)argv;
	pthread_detach(pthread_self());
		
	printf("AppStartTimer start!\n");
	signal(SIGALRM, time_val->func);
	memset(&tick, 0, sizeof(tick));
	
	//Timeout to run first time
	tick.it_value.tv_sec = time_val->interval_time;
	tick.it_value.tv_usec = 0;
	
	//After first, the Interval time for clock
	tick.it_interval.tv_sec = time_val->interval_time;
	tick.it_interval.tv_usec = 0;
	
	if(setitimer(ITIMER_REAL, &tick, NULL) < 0)
	{
		printf("Set timer failed!\n");
	}
	
	/*while(1)
	{
		pause();
	}*/

	printf("AppStartTimer exit!\n");
}


int timer_create_test(timer_para *time_val)
{
	int ret = -1;
	pthread_t timerid;
	
	/*ret=pthread_create(&timerid,NULL,(void *)start_timer,time_val); 
	if(0 != ret)
	{
		printf("create AppProcessTimer failed!ret=%d err=%s\n",ret, strerror(ret));
	}*/

	start_timer(time_val);



	return ret;
}

void test_get_thread_info(struct c_thread *ct) {
    // Get stack address from thread attributes
    void* stackAddr;
    size_t stackSize;
    pthread_attr_getstack(&ct->tattr, &stackAddr, &stackSize);
    printf("Stack Address: %p\n", stackAddr);
    printf("Stack Size: %p\n", stackSize);
}

void timer_callback_func()
{
	printf("timer print %d second\n",i*10);
	i++;

    

    /*stop the thread*/
    /*only stall at first stage in pipeline*/

    int cid = 16; // get or calculate
    struct c_thread *ct = cvms[cid].threads;
    pthread_t tid = ct->tid;
    /*int ret = pthread_suspend(tid);
	if(ret != 0) {
		perror("pthread_suspend error");
		printf("ret = %d\n", ret);
		return ;
	}*/

	printf("Thread ID: %lu\n", pthread_self());
	printf("test tid: %lu\n", tid);


    /*save state here*/

    test_get_thread_info(ct);


    //pthread_resume(tid);

}

void print_thread_attr() {
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    int result = pthread_attr_get_np(pthread_self(), &attr);
    if (result != 0) {
        fprintf(stderr, "Failed to get thread attributes\n");
        return ;
    }

    // Get stack address from thread attributes
    void* stackAddr;
    size_t stackSize;
    pthread_attr_getstack(&attr, &stackAddr, &stackSize);
    printf("Stack2 Address: %p\n", stackAddr);
    printf("Stack2 Size: %p\n", stackSize);

    // 使用 pthread_attr_getXXX 函数来获取线程属性的各种信息
    // 例如 pthread_attr_getstacksize, pthread_attr_getguardsize 等

    pthread_attr_destroy(&attr);
    printf("VM_MAXUSER_ADDRESS:%p\n", VM_MAXUSER_ADDRESS);
}

void signal_handler(int signo, siginfo_t *info, void *context) {
    // 在接收到信号的线程上下文中执行信号处理程序
	ucontext_t *me = (ucontext_t *) context;
	siginfo_t *infox = (siginfo_t *) info;



#if 1
    print_thread_attr();
#endif



    printf("Signal %d received in thread %lu\n", signo, pthread_self());
	print_context(me);
	timer_callback_func();



    /* 选择另一个上下文来调度 */ 
    setcontext(me); 

}


void stand_timer(void *argv) {
    pthread_detach(pthread_self());

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    // 设置定时器
    struct itimerval timer;
    timer.it_interval.tv_sec = 10;  // 1 秒间隔
    timer.it_interval.tv_usec = 0;
    timer.it_value.tv_sec = 10;     // 初始延迟 1 秒
    timer.it_value.tv_usec = 0;
	if(setitimer(ITIMER_REAL, &timer, NULL) < 0)
	{
		printf("Set timer failed!\n");
	}

    while(1) {
        sleep(1);
    }
}


int start_timers_context() {
    // 设置信号处理程序
    /*struct sigaction sa;
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);*/

    /*struct sigaction sa;
    sa.sa_sigaction = timer_callback_func;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);*/

    




	int ret = -1;
	pthread_t timerid;
    ret=pthread_create(&timerid,NULL,(void *)stand_timer,NULL); 
	if(0 != ret)
	{
		printf("create AppProcessTimer failed!ret=%d err=%s\n",ret, strerror(ret));
	}

    return 0;
}

void ATF_REQUIRE(bool target) {
    if(target == false) {
        exit(-1);
    }
}

void ATF_CHECK(bool target) {
    if(target == false) {
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        exit(-1);
    }
}

int ss_just_test() 
{
	stack_t ss = {
		.ss_size = SIGSTKSZ,
	};
	stack_t oss = {
		.ss_size = 0,
	};

	ss.ss_sp = malloc(ss.ss_size);
	ATF_REQUIRE(ss.ss_sp != NULL);
	ATF_REQUIRE(sigaltstack(&ss, &oss) == 0);

	// There should be no signal stack currently configured.
	ATF_CHECK(oss.ss_sp == NULL);
	ATF_CHECK(oss.ss_size == 0);
	ATF_CHECK((oss.ss_flags & SS_DISABLE) != 0);
	ATF_CHECK((oss.ss_flags & SS_ONSTACK) == 0);

	struct sigaction sa = {
		.sa_sigaction = signal_handler,
		.sa_flags = SA_ONSTACK | SA_SIGINFO,
	};
	ATF_REQUIRE(sigemptyset(&sa.sa_mask) == 0);
	ATF_REQUIRE(sigaction(SIGALRM, &sa, NULL) == 0);
	//ATF_REQUIRE(sigaction(SIGUSR2, &sa, NULL) == 0);
	//ATF_REQUIRE(raise(SIGALRM) == 0);

    printf("ss_just_test\n");

	int ret = -1;
	pthread_t timerid;
    ret=pthread_create(&timerid,NULL,(void *)stand_timer,NULL); 
	if(0 != ret)
	{
		printf("create AppProcessTimer failed!ret=%d err=%s\n",ret, strerror(ret));
	}

    return 0;
}












