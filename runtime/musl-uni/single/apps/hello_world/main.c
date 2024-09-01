#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>

#define MSG "hello world, just a hostcall test here \n"

#define MSGX "congrats, file test success! \n"

#define MSGY "1"

#define SIZE 100000000

void *my_malloc(size_t size);
void my_free(void *ptr);
void *my_realloc(void *ptr, size_t size);


double compute_flops_benchmark(double init) {
    struct timeval start, end;
    host_gettimeofday(&start, NULL);

    double sum = init;
    for(int i=0;i<1;i++) {
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


void app_main() {
    printf("hello world here! \n ");


    char *buffer = (char *)my_malloc(100);
    if(buffer == NULL) {
        printf("test");
    }
    memcpy(buffer, MSGX, strlen(MSGX));
    printf("buffer: %s", buffer);


	char buf[32];
	char cap[16];		//place to store the capability
	long size;

    int fd = host_open("testfile", 0, 0666);
    if (fd == -1) {
        printf("open error\n");
        return;
    }


    struct timeval start, end;
    host_gettimeofday(&start, NULL);

	int i = 0;
    int acc = 0;
    while(i<10) {
		i++;
        printf(" times: %d \n ", i);
        double val = 1000.0*i;
        compute_flops_benchmark(val); // test, about 10s?
        acc += 1;
        if (host_write(fd, MSGY, 1) == -1) {
            printf("write error MSGY\n");
            return;
        }
		
    }

    host_gettimeofday(&end, NULL);
    unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));
    printf("finish test runtime in %f\n",(now - then) / 1000.0);


    /*if (host_write(fd, MSGX, (long)sizeof(MSGX)) == -1) {
        printf("write error 3\n");
        return;
    }*/


    struct stat st;
    if (host_fstat(fd, &st) != 0) {
        perror("Failed to get file status");
        close(fd);
        return;
    }
    int current_pos = host_lseek(fd, 0, SEEK_CUR);
    if (current_pos == -1) {
        perror("Failed to get current file position");
        return;
    }
    
    // fd test
    if(st.st_size == acc && current_pos == acc) {
        printf("fd test success!\n");
    }
    else {
        printf("st.st_size: %d, current_pos: %d, acc: %d\n", st.st_size, current_pos, acc);
    }

    close(fd);

    c_out_3(1, MSG, (long)sizeof(MSG), 0);
    printf("out success! \n ");

    //host_exit(0);

    return ;


}



