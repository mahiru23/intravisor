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



    close(sock);
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

    close(new_socket);
    close(server_fd);

    return 0;
}


// send is unreliable
int send_all(int sock, void *buf, int size) {
    int total_bytes_sent = 0;
    int bytes_left = size;
    while (total_bytes_sent < size) {
        ssize_t bytes_sent = send(sock, buf + total_bytes_sent, bytes_left, MSG_NOSIGNAL);
        if (bytes_sent == -1) {
            perror("Send failed");
            return -1;
        }
        total_bytes_sent += bytes_sent;
        bytes_left -= bytes_sent;
    }
    return total_bytes_sent;
}

void heartbeat() {
    int len = -1;
    send_all(global_socket, &len, sizeof(len));
}

int send_to_backup() {
    return 0;
}

int send_to_backup2() {

    // connection test
    int len = 1000; // calcualte
    send_all(global_socket, &len, sizeof(len));

    char *packet = (char *)malloc(len*sizeof(char));
    if (packet == NULL) {
        perror("malloc packet error");
        exit(EXIT_FAILURE);
    }

    // thread context
    struct thread_snapshot *ctx; // get from ?
    memcpy(packet, (void *)ctx, sizeof(struct thread_snapshot));


    // capfiles

    int dirty_page_num = 8;
    for(int i=0;i<dirty_page_num;i++) {
        // page
        ;
    }

    // tag_valid (todo: run-length-code?)



    send_all(global_socket, packet, len);
    free(packet);
    return 0;
}














