
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>

#define MSG "hello world, just a hostcall test here \n"

#define PAGE_SIZE 4096

void *my_malloc(size_t size);
void my_free(void *ptr);
void *my_realloc(void *ptr, size_t size);


#define SIZE 100000000


double compute_iops_benchmark() {
    struct timeval start, end;
    host_gettimeofday(&start, NULL);

    long long sum = 0;
    for(int i=0;i<50000;i++) {
        for (int i = 0; i < SIZE; i++) {
            sum += i % (i + 1);
        }
        sum = sum/100007+i;
    }
    printf("compute_iops_benchmark sum: %ld\n", sum);

    host_gettimeofday(&end, NULL);
    unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));

    double res = (now - then) / 1000.0;
    printf("compute_iops_benchmark: in %lf\n", res);
    return res;
}


double compute_flops_benchmark() {
    struct timeval start, end;
    host_gettimeofday(&start, NULL);

    double sum = 1000.0;
    for(int i=0;i<50;i++) {
        for (int j = 0; j < SIZE; j++) {
            sum += (j * 1.0) / (j + 1.0);
        }
        sum = sum/100007+i;
    }
    printf("compute_flops_benchmark sum: %lf\n", sum);

    host_gettimeofday(&end, NULL);
    unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));

    double res = (now - then) / 1000.0;
    printf("compute_flops_benchmark: in %lf\n", res);
    return res;
}

// Test the performance of capturing & saving lots of dirty pages
double dirty_page_benchmark(int avg_page_num) {
    struct timeval start, end;
    host_gettimeofday(&start, NULL);

    /*--------------------------------*/
    char *temp_buffer = (char *)my_malloc(avg_page_num * PAGE_SIZE);
    if(temp_buffer == NULL) {
        printf("my_malloc error\n");
    }

    int seq_size = (64.0*10000000)/avg_page_num;

    for(int seq=0;seq<seq_size;seq++) {
        for(int i=0;i<avg_page_num;i++) {
            temp_buffer[i*PAGE_SIZE + ((i+seq)%PAGE_SIZE)] = (char)(i%128);
        }
    }

    my_free(temp_buffer);
    /*--------------------------------*/

    host_gettimeofday(&end, NULL);
    unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));

    double res = (now - then) / 1000.0;
    printf("dirty_page_benchmark: avg_page_num: %d, in %lf\n", avg_page_num, res);
    return res;
}

double disk_benchmark() {
    struct timeval start, end;
    host_gettimeofday(&start, NULL);

    /*--------------------------------*/
    int fd = host_open("testfile", 0, 0666);
    if (fd == -1) {
        printf("open error\n");
        return 0;
    }

    int len = 1024;
    char *write_buffer = (char *)my_malloc(len);
    if(write_buffer == NULL) {
        printf("my_malloc error\n");
    }

    for(int i=0;i<100;i++) {
        for (int j = 0; j < len; j++) {
            write_buffer[i] = ('0'+i%10);
        }

        for (int j = 0; j < 100000; j++) {
            if (host_write(fd, write_buffer, len) == -1) {
                printf("write error\n");
                return 0;
            }
        }

        int current_pos = host_lseek(fd, 0, SEEK_CUR);
        if (current_pos == -1) {
            perror("Failed to get current file position");
            return 0;
        }
        struct stat st;
        if (host_fstat(fd, &st) != 0) {
            perror("Failed to get file status");
            close(fd);
            return 0;
        }
        if(!(st.st_size == len*100000 && current_pos == len*100000)) {
            printf("st.st_size: %d, current_pos: %d\n", st.st_size, current_pos);
            return 0;
        }
        if (host_lseek(fd, 0, SEEK_SET) == -1) {
            perror("host_lseek set error");
            return 0;
        }
    }


    close(fd);

    /*--------------------------------*/

    host_gettimeofday(&end, NULL);
    unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));

    double res = (now - then) / 1000.0;
    printf("disk_benchmark: in %lf\n", res);
    return res;
}


void app_main() {
    printf("start benchmark test! \n ");

    struct timeval start, end;
    host_gettimeofday(&start, NULL);

    /*--------------------------------------------*/
    compute_flops_benchmark();
    compute_iops_benchmark();
    for(int i=1;i<=1024;i*=2) {
        dirty_page_benchmark(i);
    }
    disk_benchmark();
    /*--------------------------------------------*/

    host_gettimeofday(&end, NULL);
    unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));
    printf("benchmark finish time: %lf s\n",(now - then) / 1000.0);

    return ;
}