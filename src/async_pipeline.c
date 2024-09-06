#include "monitor.h"

int full_copy_flag = 0;

// a producer-consumer model queue
queue master_event_queue; 
queue backup_event_queue;

int global_transmit_count = 0;
double global_transmit_time = 0.0;
double max_transmit_time = 0.0;
double min_transmit_time = 10000.0;
pthread_mutex_t transmit_mtx = PTHREAD_MUTEX_INITIALIZER;

double suspend_time_array[2000];
double transmit_time_array[2000];

int network_latency = 0;
int queue_capacity_threshold = 1000;

// single thread
void async_pipeline_master_init() {
	int ret = -1;
	pthread_t id;
    stack_cap_tags_sparse_size = 200;
    stack_cap_tags_sparse_now_length = 0;
    stack_cap_tags_sparse = (int *)malloc(stack_cap_tags_sparse_size * sizeof(int)); // init with 200 cap, will increase
    if (stack_cap_tags_sparse == NULL) {
        perror("malloc stack_cap_tags_sparse error");
        exit(EXIT_FAILURE);
    }

	ret = pthread_create(&id, NULL, (void *)async_pipeline_master_impl, NULL); 
	if(ret != 0) {
        perror("pthread_create async_pipeline_master_impl");
	}
}

void async_pipeline_master_impl() {
    mask_signal(SIGALRM);

    // set buffer-queue to send
    queue *que = &master_event_queue;

    while(1) {

        fd_set readset, writeset;
        FD_ZERO(&readset);
        FD_ZERO(&writeset);
        FD_SET(global_socket, &readset);
        FD_SET(global_socket, &writeset);

        struct timeval tm; // would update by select
        tm.tv_sec = QUEUE_TIMEOUT_SEC;
        tm.tv_usec = QUEUE_TIMEOUT_USEC;

        int select_ret;
        int size = get_size(que);
        
        if(size == 0) { // queue empty
            //select_ret = select(FD_SETSIZE, &readset, 0, 0, &tm);
            usleep(QUEUE_EMPTY_TIMEOUT_USEC);
            continue;
        }
        else {
            if(size > queue_capacity_threshold) {
                printf("master queue size > queue_capacity_threshold(%d), timeout is too long!\n", queue_capacity_threshold);
            }
            //select_ret = select(FD_SETSIZE, &readset, &writeset, 0, &tm);
            select_ret = select(FD_SETSIZE, 0, &writeset, 0, &tm);
        }

        if (select_ret == -1) {
            if (errno != EINTR) {
                perror("async_pipeline_master_impl: select failed");
                printf("async_pipeline_master_impl: crashed\n");
                break;
            }
        } else if (select_ret == 0) {
            printf("async_pipeline_master_impl: select timeout\n");
            continue;
        } else {
            if (FD_ISSET(global_socket, &writeset)) {
                // write sendqueue
                // heartbeat & file/socket ops & checkpoint
                int flag = 0;
                while(get_size(que) != 0) {
#if ANALYSE
    pthread_mutex_lock(&transmit_mtx);
    struct timeval start, end;
    gettimeofday(&start, NULL);
    int node_type = que->top->type;
#endif
                    node *n = que->top;
                    //printf("send n->type: %d\n", n->type);
                    if(send_all(global_socket, n, sizeof(node)) == -1) {
                        flag = 1;
                        printf("async_pipeline_master_impl: send node error\n");
                        break;
                    }

                    if(send_all(global_socket, n->payload, n->len) == -1) {
                        flag = 1;
                        printf("async_pipeline_master_impl: send payload error\n");
                        break;
                    }
                    if(n->payload != NULL) {
                        free(n->payload);
                    }
                    n = pop_front(que);
                    free(n);
#if ANALYSE
    if(node_type == CHECKPOINT || node_type == FILE_OPS) {
        if(network_latency != 0) {
            while(1) {
                usleep(network_latency*1000); // simulate 10ms latency
                int loss_base = 10000/network_latency; // 100 ms = 1% loss rate
                int temp = rand()%loss_base;
                if(temp != 0) { 
                    break;
                }
            }
        }

        gettimeofday(&end, NULL);
        unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
        unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));
        double transmit_time = (now - then) / 1000.0;
        if(global_transmit_count<2000)
            transmit_time_array[global_transmit_count] = transmit_time;
        global_transmit_count++;
        global_transmit_time += transmit_time;
        max_transmit_time = max(transmit_time, max_transmit_time);
        min_transmit_time = min(transmit_time, min_transmit_time);
    }
    pthread_mutex_unlock(&transmit_mtx);
#endif
                }
                if(flag == 1) {
                    break;
                }
            }
        }
    }
    master_failure_handler();
}

/*file & network ops, async send*/
/*use queue/node in monitor, i dont know whether works, need more test*/
void send_to_backup_op(long t5, long a0, long a1, long a2, long a3) {
    queue *que = &master_event_queue;
    node *n = (node *)malloc(sizeof(node));
    if (n == NULL) {
        perror("malloc node error");
        exit(EXIT_FAILURE);
    }

    //struct vm_event *v = (struct vm_event *)malloc(sizeof(struct vm_event));
    struct vm_event v;
    init_vm_event(&v, t5, a0, a1, a2, a3);
    n->event = v;
    n->id = master_checkpoint;
    n->type = FILE_OPS;
    n->len = 0;
    n->payload = NULL;
    
    master_checkpoint++;

	switch (t5) {
	case 803: // close
        push_back(que, n);
        break;
    case 808: { // truncate
        size_t len = strlen((char *)a0) + 1; // include '\0'
        char* pathname = (char *)malloc(len);
        if (pathname == NULL) {
            perror("malloc pathname error");
            exit(EXIT_FAILURE);
        }
        strcpy(pathname, (char *)a0);
        n->len = len;
        n->payload = pathname;
        push_back(que, n);
        break;
    }

    case 811: { // open
        size_t len = strlen((char *)a0) + 1; // include '\0'
        char* pathname = (char *)malloc(len);
        if (pathname == NULL) {
            perror("malloc pathname error");
            exit(EXIT_FAILURE);
        }
        strcpy(pathname, (char *)a0);
        n->len = len;
        n->payload = pathname;
        push_back(que, n);
		break;
    }
	case 810: { // write
        char* write_buffer = (char *)malloc(a2);
        if (write_buffer == NULL) {
            perror("malloc write_buffer error");
            exit(EXIT_FAILURE);
        }
        memcpy((void *)(write_buffer), (void *)(a1), a2);
        n->len = a2;
        n->payload = write_buffer;
        push_back(que, n);
		break;
    }
	default:
		printf("send_to_backup_op: unknown t5 %d\n", (int) t5);
		while(1) ;
    }
}

void kill_backup() {
    queue *que = &master_event_queue;
    node *n = (node *)malloc(sizeof(node));
    if (n == NULL) {
        perror("malloc node error");
        exit(EXIT_FAILURE);
    }

    n->id = master_checkpoint;
    n->type = KILL_BACKUP;
    n->len = 0;
    n->payload = NULL;
    master_checkpoint++;
    push_back(que, n);
}

void async_heartbeat() {
    queue *que = &master_event_queue;
    node *n = (node *)malloc(sizeof(node));
    if (n == NULL) {
        perror("malloc node error");
        exit(EXIT_FAILURE);
    }
    n->id = master_checkpoint;
    n->type = HEARTBEAT;
    n->len = 0;
    n->payload = NULL;
    master_checkpoint++;
    push_back(que, n);
}

// master -> backup
int async_master_to_backup(struct c_thread *ct, int dirty_page_num, int valid_cap_num) {

    struct files_detail packet_index;
    packet_index.context_len = get_filesize("snapshot/context_dump.bin");
    packet_index.capfiles_len = get_filesize("snapshot/capfiles_dump.bin");
    packet_index.dirty_page_map_len = sizeof(dirty_page_map);
    packet_index.stack_page_len = dirty_page_num * PAGE_SIZE;
    packet_index.stack_cap_tags_len = valid_cap_num * sizeof(int);
    packet_index.fd_list_len = open_fd_list_size();
#if ASYNC_PIPELINE
    packet_index.heap_dirty_page_packet_len = global_heap_dirty_page_num*sizeof(struct page);
#elif
    packet_index.heap_dirty_page_packet_len = 0;
#endif

    int len =   sizeof(packet_index) + \
                packet_index.context_len + \ 
                packet_index.capfiles_len + \
                packet_index.dirty_page_map_len + \
                packet_index.stack_page_len + \
                packet_index.stack_cap_tags_len + \
                packet_index.fd_list_len + \
                packet_index.heap_dirty_page_packet_len;

    unsigned long pos = 0;
    char *packet = (char *)malloc(len*sizeof(char));
    if (packet == NULL) {
        perror("malloc packet error");
        exit(EXIT_FAILURE);
    }

    // packet_index
    memcpy((packet+pos), (void *)(&packet_index), sizeof(packet_index));
    pos += sizeof(packet_index);

    // thread context
    int fd_context = open("snapshot/context_dump.bin", O_RDONLY);
    if (fd_context == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    size_t bytes_read = read(fd_context, (packet+pos), packet_index.context_len);
    if (bytes_read != packet_index.context_len) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    close(fd_context);
    pos += packet_index.context_len;

    // capfiles
    int fd = open("snapshot/capfiles_dump.bin", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    bytes_read = read(fd, (packet+pos), packet_index.capfiles_len);
    if (bytes_read != packet_index.capfiles_len) {
        perror("read");
        exit(EXIT_FAILURE);
    }
    close(fd);
    pos += packet_index.capfiles_len;

    // dirty_page_map
    memcpy((packet+pos), (void *)dirty_page_map, packet_index.dirty_page_map_len);
    pos += packet_index.dirty_page_map_len;

    for(int i=0;i<PAGE_NUM;i++) {
        if (dirty_page_map[i] & MINCORE_MODIFIED) {
            memcpy((packet+pos), (void *)(ct->stack+i*PAGE_SIZE), PAGE_SIZE);
            pos += PAGE_SIZE;
        }
    }

    // tag_valid (todo: run-length-code?)
    memcpy((packet+pos), (void *)(stack_cap_tags_sparse), packet_index.stack_cap_tags_len);
    pos+=packet_index.stack_cap_tags_len;

    memcpy_fd_list((packet+pos), packet_index.fd_list_len);
    pos+=packet_index.fd_list_len;

#if HEAP_SNAPSHOT
    memcpy((packet+pos), (void *)(heap_dirty_page_packet), packet_index.heap_dirty_page_packet_len);
    free(heap_dirty_page_packet);
#endif

    queue *que = &master_event_queue;
    node *n = (node *)malloc(sizeof(node));
    if (n == NULL) {
        perror("malloc node error");
        exit(EXIT_FAILURE);
    }
    n->id = master_checkpoint;
    n->type = CHECKPOINT;
    n->len = len;
    n->payload = packet;
    master_checkpoint++;
    push_back(que, n);

    return 0;
}

void async_pipeline_backup_init() {
    stack_cap_tags_sparse_size = 200;
    stack_cap_tags_sparse_now_length = 0;
    stack_cap_tags_sparse = (int *)malloc(stack_cap_tags_sparse_size * sizeof(int)); // init with 200 cap, will increase
    if (stack_cap_tags_sparse == NULL) {
        perror("malloc stack_cap_tags_sparse error");
        exit(EXIT_FAILURE);
    }
}

int release_queue(queue* que) {
	while(get_size(que) != 0) {
		node *n = que->top;

        switch (n->event.t5) {
        case 803: { // close
            int master_fd = n->event.a0;
            close(master_fd);
            break;
        }
        case 808: {// truncate
            char *pathname = n->payload;
            if(truncate(pathname, n->event.a1) == -1) {
                perror("cannot truncate");
                return -1;
            }
            break;
        }
        case 811: {// open
            char *pathname = n->payload;
            int master_fd = n->event.a3;
            if(open_fd_backup(master_fd, pathname, n->event.a1, n->event.a2) == -1) {
                perror("cannot open master_fd");
                return -1;
            }
            break;
        }
        case 810: {// write
            char *write_buffer = n->payload;
            int master_fd = n->event.a0;
            int current_pos = n->event.a3;
            if (lseek(master_fd, current_pos, SEEK_SET) == -1) {
                perror("lseek error");
                return -1;
            }

            if (write(master_fd, write_buffer, n->len) == -1) {
                perror("write master_fd");
                close(master_fd);
                exit(EXIT_FAILURE);
            }
            break;
        }

        // maybe more (fcntl/lseek/unlink/...)
        default:
            printf("send_to_backup_op: unknown t5 %d\n", (int) n->event.t5);
            while(1);
        }

		if(n->payload != NULL) {
			free(n->payload);
		}
		n = pop_front(que);
		free(n);
	}
}

// TODO: store in memory
// sync to disk
int save_snapshot_to_disk(char *packet) {
    int pos = 0;
    struct files_detail packet_index;
    memcpy((void *)(&packet_index), (packet+pos), sizeof(packet_index));
    pos += sizeof(packet_index);

    pos += snapshot_to_file("snapshot/context_dump.bin", (packet + pos), packet_index.context_len, 0);
    pos += snapshot_to_file("snapshot/capfiles_dump.bin", (packet + pos), packet_index.capfiles_len, 0);

    memcpy((void *)(dirty_page_map), (packet+pos), packet_index.dirty_page_map_len);
    pos += packet_index.dirty_page_map_len;

    int get_page_num = 0;
    for(int i=0;i<PAGE_NUM;i++) {
        if (dirty_page_map[i] & MINCORE_MODIFIED) {
            pos += snapshot_to_file("snapshot/stack_dump.bin", (packet + pos), PAGE_SIZE, i*PAGE_SIZE);
        }
    }

    pos += snapshot_to_file("snapshot/stack_cap_tags.bin", (packet + pos), packet_index.stack_cap_tags_len, 0);

    pos += snapshot_to_file("snapshot/fd_list.bin", (packet + pos), packet_index.fd_list_len, 0);

#if HEAP_SNAPSHOT
    save_heap_dirty_page_to_disk(packet+pos, packet_index.heap_dirty_page_packet_len);
#endif

    
#if DEBUG
    printf("save_snapshot_to_disk, over\n");
#endif
    return 0;
}

int save_snapshot_to_memory(char *packet) {
    int pos = 0;
    struct files_detail packet_index;
    memcpy((void *)(&packet_index), (packet+pos), sizeof(packet_index));
    pos += sizeof(packet_index);

    memcpy((void *)backup_context_buffer, (packet + pos), packet_index.context_len);
    pos += packet_index.context_len;

    if(packet_index.capfiles_len > malloc_usable_size(backup_capfiles_buffer)) {
        char *new_backup_capfiles_buffer = realloc(backup_capfiles_buffer, packet_index.capfiles_len);
        if(new_backup_capfiles_buffer == NULL) {
            perror("realloc backup_capfiles_buffer");
            free(backup_capfiles_buffer);
            exit(EXIT_FAILURE);
        }
        backup_capfiles_buffer = new_backup_capfiles_buffer;
    }
    memcpy((void *)backup_capfiles_buffer, (packet + pos), packet_index.capfiles_len);
    pos += packet_index.capfiles_len;

    memcpy((void *)(dirty_page_map), (packet+pos), packet_index.dirty_page_map_len);
    pos += packet_index.dirty_page_map_len;

    int get_page_num = 0;
    for(int i=0;i<PAGE_NUM;i++) {
        if (dirty_page_map[i] & MINCORE_MODIFIED) {
            memcpy((void *)(backup_stack_buffer + i*PAGE_SIZE), (packet + pos), PAGE_SIZE);
            pos += PAGE_SIZE;
        }
    }

    stack_cap_tags_sparse_now_length = packet_index.stack_cap_tags_len/sizeof(int);
    if(stack_cap_tags_sparse_now_length > stack_cap_tags_sparse_size) {
        int new_size = min(stack_cap_tags_sparse_now_length + 200, STACK_CAP_LINE);
        char *new_stack_cap_tags_sparse = realloc(stack_cap_tags_sparse, new_size * sizeof(int));
        if(new_stack_cap_tags_sparse == NULL) {
            perror("realloc backup_capfiles_buffer");
            free(stack_cap_tags_sparse);
            exit(EXIT_FAILURE);
        }
        stack_cap_tags_sparse = new_stack_cap_tags_sparse;
        stack_cap_tags_sparse_size = new_size;
    }

    memcpy((void *)stack_cap_tags_sparse, (packet+pos), packet_index.stack_cap_tags_len);
    pos += packet_index.stack_cap_tags_len;

    save_fd_list_backup(packet+pos);
    pos += packet_index.fd_list_len;

#if HEAP_SNAPSHOT
    save_heap_dirty_page_to_memory(packet+pos, packet_index.heap_dirty_page_packet_len);
#endif


#if DEBUG
    printf("save_snapshot_to_memory, over\n");
#endif
    

    return 0;
}

int async_backup_server_impl() {
    if(is_master || (!backup_valid_flag)) {
        return -1;
    }

    queue *que = &backup_event_queue;
    node *n = (node *)malloc(sizeof(node));
    if (n == NULL) {
        perror("malloc node error");
        exit(EXIT_FAILURE);
    }

    if(recv_all(global_socket, n, sizeof(node)) == -1) {
        //backup_failure_handler();
        return -1;
    }

    if(n->type == HEARTBEAT) { // heartbeat (not checkpoint)
        return 0;
    }
    else if(n->type == FILE_OPS || n->type == SOCKET_OPS) {
        push_back(que, n);
        if(n->payload != NULL) {
            char *write_buffer = (char *)malloc(n->len);
            if(recv_all(global_socket, write_buffer, n->len) == -1) {
                //backup_failure_handler();
                free(write_buffer);
                return -1;
            }
            n->payload = write_buffer;
        }
        return 0;
    }
    else if(n->type == CHECKPOINT) { // checkpoint
        int snapshot_size = n->len;
        char *packet = (char *)malloc(snapshot_size);
        if (packet == NULL) {
            perror("malloc packet error");
            exit(EXIT_FAILURE);
        }
        if(recv_all(global_socket, packet, snapshot_size) == -1) {
            //backup_failure_handler();
            free(packet);
            return -1;
        }
        release_queue(que);
        save_snapshot_to_memory(packet);
        save_snapshot_to_disk(packet);
        free(packet);
        free(n);
    }
    else if(n->type == KILL_BACKUP) { // finish backup
        release_queue(que);
        free(n);
        return -2;
    }
    else {
        perror("async_backup_server_impl: error node type!\n");
        free(n);
        exit(-1);
    }

    return 0;
}

char *backup_context_buffer;
char *backup_capfiles_buffer;
char *backup_stack_buffer;

void backup_memory_init() {
    backup_context_buffer = (char *)malloc(sizeof(struct thread_snapshot) + REG_NUM * sizeof(int));
    if(backup_context_buffer == NULL) {
        perror("malloc backup_context_buffer");
        exit(EXIT_FAILURE);
    }

    backup_capfiles_buffer = (char *)malloc(get_capfiles_base_size());
    if(backup_capfiles_buffer == NULL) {
        perror("malloc backup_capfiles_buffer");
        exit(EXIT_FAILURE);
    }

    backup_stack_buffer = (char *)malloc(STACK_SIZE);
    if(backup_stack_buffer == NULL) {
        perror("malloc backup_stack_buffer");
        exit(EXIT_FAILURE);
    }
}





