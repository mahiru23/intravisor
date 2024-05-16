#ifndef _SYS_SNAPSHOT_H_
#define _SYS_SNAPSHOT_H_

struct thread_snapshot {
    struct trapframe frame;
};

int get_thread_snapshot(pid_t pid, pthread_t tid, struct thread_snapshot *ctx);

/*
583	AUE_NULL	STD {
		int get_thread_snapshot(
		    pid_t pid,
		    pthread_t tid,
			struct thread_snapshot *ctx,
		);
	}
*/

#endif /* !_SYS_SNAPSHOT_H_ */