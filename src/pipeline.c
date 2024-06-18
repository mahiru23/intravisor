#include "monitor.h"


#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <sys/select.h>
#include <errno.h>

#define PORT 8080
#define BUF_SIZE 1024
#define TIMEOUT_SEC 5

bool master_valid_flag = false;
bool backup_valid_flag = false;
bool is_master = false;

int global_socket;
int master_checkpoint = 0;
int backup_checkpoint = 0;

int test_network_client() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE] = {0};
    const char *hello = "Hello from client";
    const char *server_ip = "127.0.0.1";

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

   if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    backup_valid_flag = true;
    global_socket = sock;


    int i=0;
    while(i<5) {
        i++;
        sleep(i);
        char hellox[30] = "test   :";
        hellox[5] = '0'+i;
        strcat(hellox, hello);

        printf("hellox: %s\n", hellox);




    // Send data to server
    ssize_t bytes_sent = send(sock, hellox, strlen(hellox), MSG_NOSIGNAL);
    if (bytes_sent == -1) {
        perror("Send failed??????????????????????");
        close(sock);
        break;
        return -1;
    }
        printf("Hello message sent %d\n", bytes_sent);
        
    }

    printf("client over\n");
    //close(sock);
    return 0;
}

int test_network_server() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUF_SIZE] = {0};
    const char *hello = "Hello from server";

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR , &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    struct timeval timeout;
    timeout.tv_sec = DISCONNECTION_TIMEOUT;
    timeout.tv_usec = 0;

    if (setsockopt(new_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    master_valid_flag = true;
    global_socket = new_socket;


    int i=0;
    while(i<5) {
        ssize_t bytes_read = read(new_socket, buffer, BUF_SIZE);
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("Read timed out after %d seconds.\n", i+1);
                break;
                close(new_socket);
                close(server_fd);
                exit(-1);
                
            } else {
                perror("read failed");
            }
        } else if (bytes_read == 0) {
            printf("Client disconnected\n");
        } else {
            printf("Message from client: %s\n", buffer);
        }
        i++;
    }

    printf("over1\n");
    exit(-1);
printf("over2\n");

    //close(new_socket);
    //close(server_fd);

    return 0;
}

int heartbeat(int size) {
    int len = size;
    return send_all(global_socket, &len, sizeof(len));
}

int master_network_setup() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE] = {0};
    const char *hello = "Hello from client";
    const char *server_ip = "127.0.0.1";

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("master_network_setup, socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("master_network_setup, invalid address or address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

   if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("master_network_setup, connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    is_master = true;
    master_valid_flag = true;
    backup_valid_flag = true;
    global_socket = sock;

    return 0;
}

// master -> backup
int master_to_backup(struct c_thread *ct, int dirty_page_num) {

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

    if(heartbeat(len) == -1) { // connection test
        master_failure_handler();
    }

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

    if(send_all(global_socket, packet, len) == -1) {
        master_failure_handler();
    }

    printf("send to backup over!\n");
    free(packet);

    if(recv_all(global_socket, &backup_checkpoint, sizeof(backup_checkpoint)) == -1) {
        master_failure_handler();
    }

    return 0;
}

// global socket
int backup_network_setup() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR , &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("backup_network_setup, listening\n");

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("backup_network_setup, accept connection from master\n");

    struct timeval timeout;
    timeout.tv_sec = DISCONNECTION_TIMEOUT;
    timeout.tv_usec = 0;

    if (setsockopt(new_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    is_master = false;
    backup_valid_flag = true;
    master_valid_flag = true;
    global_socket = new_socket;

    printf("backup_network_setup, over\n");

    return 0;
}

// backup event loop
int backup_server_impl();
int backup_server() {
    int ret = 0;
    while(1) {
        ret = backup_server_impl();
        if(ret == -1) {
            break;
        }
    }
    printf("master crashed, backup -> master\n");
    return 0;
}

// update local snapshot
// backup -> master
int backup_server_impl() {
    if(is_master || (!backup_valid_flag)) {
        return -1;
    }

    int snapshot_size;
    if(recv_all(global_socket, &snapshot_size, sizeof(snapshot_size)) == -1) {
        backup_failure_handler();
    }
    if(snapshot_size == -1) { // heartbeat
        return 0;
    }

    int pos = 0;
    char *packet = (char *)malloc(snapshot_size);
    if (packet == NULL) {
        perror("malloc packet error");
        exit(EXIT_FAILURE);
    }

    if(recv_all(global_socket, packet, snapshot_size) == -1) {
        backup_failure_handler();
    }

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

    // send checkpoint to master
    backup_checkpoint += 1;
    if(send_all(global_socket, &backup_checkpoint, sizeof(backup_checkpoint)) == -1) {
        backup_failure_handler();
    }

    return 0;
}


