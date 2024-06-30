#include "monitor.h"


int global_send_buffer_size;
char* global_send_buffer;

// single thread
void init_async_pipeline_master() {
	int ret = -1;
	pthread_t id;

    global_send_buffer_size = (1<<24); // 16 MB
    global_send_buffer = (char *)malloc(global_send_buffer_size);
    if (global_send_buffer_size == NULL) {
        perror("malloc global_send_buffer");
        exit(EXIT_FAILURE);
    }

	ret = pthread_create(&id, NULL, (void *)async_pipeline_master_impl, NULL); 
	if(ret != 0) {
        perror("pthread_create global_send_buffer");
	}
}

void async_pipeline_master_impl() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    // set buffer-queue to send

    while(1) {

        fd_set readset, writeset;
        FD_ZERO(&readset);
        FD_ZERO(&writeset);
        FD_SET(global_socket, &readset);
        FD_SET(global_socket, &writeset);

        timeval tm; // would update by select
        tm.tv_sec = 10;
        tm.tv_usec = 0;

        int select_ret;
        if(send_queue.empty()) {
            select_ret = select(FD_SETSIZE, &readset, 0, 0, &tm);
        }
        else {
            select_ret = select(FD_SETSIZE, &readset, &writeset, 0, &tm);
        }


        if (ret == -1) {
            if (errno != EINTR) {
                perror("async_pipeline_master_impl: select failed");
                exit(-1);
            }
        } else if (ret == 0) {
            printf("async_pipeline_master_impl: select timeout\n");
            continue;
        } else {
            // ... 
            if (FD_ISSET(global_socket, &readset)) {
                // read request from backup
                // may not need???
            }

            if (FD_ISSET(global_socket, &writeset)) {
                // write sendqueue
                // heartbeat & file ops & checkpoint
            }
        }


    }



}

