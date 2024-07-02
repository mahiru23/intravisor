#include "monitor.h"


/*int global_send_buffer_size;
char* global_send_buffer;*/

queue master_event_queue;
queue backup_event_queue;

// single thread
void async_pipeline_master_init() {
	int ret = -1;
	pthread_t id;

    /*global_send_buffer_size = (1<<24); // 16 MB
    global_send_buffer = (char *)malloc(global_send_buffer_size);
    if (global_send_buffer == NULL) {
        perror("malloc global_send_buffer");
        exit(EXIT_FAILURE);
    }*/

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
    queue *que = &master_event_queue;

    while(1) {

        fd_set readset, writeset;
        FD_ZERO(&readset);
        FD_ZERO(&writeset);
        FD_SET(global_socket, &readset);
        FD_SET(global_socket, &writeset);

        struct timeval tm; // would update by select
        tm.tv_sec = 1;
        tm.tv_usec = 0;

        int select_ret;
        // may need queue lock?????
        if(que->top == NULL) { // queue empty
            //select_ret = select(FD_SETSIZE, &readset, 0, 0, &tm);
            usleep(10);
            continue;
        }
        else {
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
            // ... 
            if (FD_ISSET(global_socket, &readset)) {
                // read request from backup
                // may not need???
                ;
            }

            if (FD_ISSET(global_socket, &writeset)) {
                // write sendqueue
                // heartbeat & file/socket ops & checkpoint
                int flag = 0;
                while(que->top != NULL) {
                    node *n = que->top;
                    if(send_all(global_socket, n, sizeof(node)) == -1) {
                        flag = 1;
                        break;
                    }
                    if(send_all(global_socket, n->payload, n->len) == -1) {
                        flag = 1;
                        break;
                    }
                    if(n->payload != NULL) {
                        free(n->payload);
                    }
                    n = pop_front(que);
                    free(n);
                }
                if(flag == 1) {
                    break;
                }
            }
        }
    }

    
    master_failure_handler();
    /*while(1) {
        sleep(1);
    }*/
}



void init_vm_event(struct vm_event* v, long t5, long a0, long a1, long a2, long a3) {
    v->t5 = t5;
    v->a0 = a0;
    v->a1 = a1;
    v->a2 = a2;
    v->a3 = a3;
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
        memcpy((void *)(a1), write_buffer, a2);
        n->len = a2;
        n->payload = write_buffer;
        push_back(que, n);

        /*send_all(global_socket, &type, sizeof(type));
        send_all(global_socket, v, sizeof(struct vm_event));
        send_all(global_socket, a1, a2);
        free(v);
        pop_back(que);*/
		break;
    }
	default:
		printf("send_to_backup_op: unknown t5 %d\n", (int) t5);
		while(1) ;
    }
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
int async_master_to_backup(struct c_thread *ct, int dirty_page_num) {

    struct files_detail packet_index;
    packet_index.context_len = get_filesize("context_dump.bin");
    packet_index.capfiles_len = get_filesize("capfiles_dump.bin");
    packet_index.dirty_page_map_len = sizeof(dirty_page_map);
    packet_index.stack_page_len = dirty_page_num * PAGE_SIZE;
    packet_index.stack_cap_tags_len = sizeof(stack_cap_tags);

    int len =   sizeof(packet_index) + \
                packet_index.context_len + \ 
                packet_index.capfiles_len + \
                packet_index.dirty_page_map_len + \
                packet_index.stack_page_len + \
                packet_index.stack_cap_tags_len;

    /*if(heartbeat(len) == -1) {
        master_failure_handler();
    }*/

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
    int fd_context = open("context_dump.bin", O_RDONLY);
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
    int fd = open("capfiles_dump.bin", O_RDONLY);
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
    memcpy((packet+pos), (void *)(stack_cap_tags), packet_index.stack_cap_tags_len);

    queue *que = &master_event_queue;
    node *n = (node *)malloc(sizeof(node));
    if (n == NULL) {
        perror("malloc node error");
        exit(EXIT_FAILURE);
    }
    n->id = master_checkpoint;
    n->type = SNAPSHOT;
    n->len = len;
    n->payload = packet;
    master_checkpoint++;
    push_back(que, n);

    return 0;
}


int release_queue(queue* que) {
	while(que->top != NULL) {
		node *n = que->top;

        switch (n->event.t5) {
        case 803: { // close
            int master_fd = n->event.a0;
            if(close_fd(master_fd) == -1) {
                perror("cannot find master_fd");
                return -1;
            }
            break;
        }
        case 808: {// truncate
            char *pathname = (char *)malloc(n->len);
            if(recv_all(global_socket, pathname, n->len) == -1) {
                backup_failure_handler();
                free(pathname);
                return -1;
            }
            if(truncate(pathname, n->event.a1) == -1) {
                perror("cannot truncate");
                return -1;
            }
            break;
        }
        case 811: {// open
            char *pathname = (char *)malloc(n->len);
            if(recv_all(global_socket, pathname, n->len) == -1) {
                backup_failure_handler();
                free(pathname);
                return -1;
            }
            if(open_fd(pathname, n->event.a1, n->event.a2) == -1) {
                perror("cannot open master_fd");
                return -1;
            }
            break;
        }
        case 810: {// write
            char *write_buffer = (char *)malloc(n->len);
            if(recv_all(global_socket, write_buffer, n->len) == -1) {
                backup_failure_handler();
                free(write_buffer);
                return -1;
            }
            int master_fd = n->event.a0;
            int backup_fd = find_backup_fd(master_fd);
            if (write(backup_fd, write_buffer, n->len) == -1) {
                perror("write backup_fd");
                close_fd(master_fd);
                exit(EXIT_FAILURE);
            }
            break;
        }

        // maybe more (fcntl/lseek/unlink/...)
        default:
            printf("send_to_backup_op: unknown t5 %d\n", (int) n->event.t5);
            while(1);
        }

		n = pop_front(que);
		free(n);
	}
}

// TODO: store in memory
// sync to disk
int save_snapshot(queue *que, node *n, char *packet) {
    int pos = 0;
    struct files_detail packet_index;
    memcpy((void *)(&packet_index), (packet+pos), sizeof(packet_index));
    pos += sizeof(packet_index);

    pos += snapshot_to_file("context_dump.bin", (packet + pos), packet_index.context_len, 0);
    pos += snapshot_to_file("capfiles_dump.bin", (packet + pos), packet_index.capfiles_len, 0);

    memcpy((void *)(&dirty_page_map), (packet+pos), packet_index.dirty_page_map_len);
    pos += packet_index.dirty_page_map_len;

    int get_page_num = 0;
    for(int i=0;i<PAGE_NUM;i++) {
        if (dirty_page_map[i] & MINCORE_MODIFIED) {
            pos += snapshot_to_file("stack_dump.bin", (packet + pos), PAGE_SIZE, i*PAGE_SIZE);
        }
    }

    pos += snapshot_to_file("stack_cap_tags.bin", (packet + pos), packet_index.stack_cap_tags_len, 0);

    printf("save, over\n");

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
        backup_failure_handler();
        return -1;
    }

    if(n->type == HEARTBEAT) { // heartbeat (not checkpoint)
        //release_queue(que);
        return 0;
    }
    else if(n->type == FILE_OPS || n->type == SOCKET_OPS) {
        push_back(que, n);
        return 0;
    }
    else if(n->type == SNAPSHOT) { // checkpoint
        int snapshot_size = n->len;
        char *packet = (char *)malloc(snapshot_size);
        if (packet == NULL) {
            perror("malloc packet error");
            exit(EXIT_FAILURE);
        }
        if(recv_all(global_socket, packet, snapshot_size) == -1) {
            backup_failure_handler();
            free(packet);
            return -1;
        }
        release_queue(que);
        save_snapshot(que, n, packet);
        free(packet);
    }
    else {
        perror("error node type!");
        exit(-1);
    }

    return 0;
}


