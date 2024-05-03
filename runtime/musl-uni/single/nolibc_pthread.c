#define _GNU_SOURCE

#include "hostcalls.h"
#include "pthread_impl.h"
#include "stdio_impl.h"
#include "libc.h"
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include "cheri_helpers.h"

int pthread_create(pthread_t * restrict res, const pthread_attr_t * restrict attrp, void *(*entry)(void *), void *restrict arg) {

	
	printf("sp before: %p \n", getCSP());

	printf("pthread flag 0 \n");
	unsigned long tid = host_thread_create(entry, arg);
	if(tid == 0)
		return ENOSYS;

//in reality it is not tid, it is thread_t created by host system
//it does not fit into tid so instead of adding another fied I reused canary

	printf("pthread flag 1 \n");
	struct pthread *new = malloc(sizeof(struct pthread));
	new->canary = tid;

	//getCSP();

	printf("sp after: %p \n", getCSP());

	*res = new;
	printf("pthread flag 2 \n");

	return 0;
}

int pthread_join(pthread_t t, void **res) {
	int ret = host_thread_join(t->canary, res);
	free(t);
	return ret;
}

void pthread_exit(void *value_ptr) {
	host_thread_exit(value_ptr);
}
