
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
    for(int i=0;i<300;i++) {
        for (int j = 0; j < SIZE; j++) {
            sum += j;
            sum %= SIZE;
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

    long long seq_size = (64.0*10000000)/avg_page_num;

    for(long long seq=0;seq<seq_size;seq++) {
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

    for(int i=0;i<3;i++) {
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

/*----------------------------------------------*/
/*benchmark: convolution & pooling*/



#define INPUT_SIZE 64
#define FILTER_SIZE 3
#define POOL_SIZE 2
#define NUM_ITERATIONS 200000

// Function to perform 2D convolution
void conv2d(float input[INPUT_SIZE][INPUT_SIZE], float filter[FILTER_SIZE][FILTER_SIZE], float output[INPUT_SIZE - FILTER_SIZE + 1][INPUT_SIZE - FILTER_SIZE + 1]) {
    for (int i = 0; i < INPUT_SIZE - FILTER_SIZE + 1; i++) {
        for (int j = 0; j < INPUT_SIZE - FILTER_SIZE + 1; j++) {
            float sum = 0.0;
            for (int k = 0; k < FILTER_SIZE; k++) {
                for (int l = 0; l < FILTER_SIZE; l++) {
                    sum += input[i + k][j + l] * filter[k][l];
                }
            }
            output[i][j] = sum;
        }
    }
}

// Function to perform 2D max pooling
void maxpool2d(float input[INPUT_SIZE - FILTER_SIZE + 1][INPUT_SIZE - FILTER_SIZE + 1], float output[(INPUT_SIZE - FILTER_SIZE + 1) / POOL_SIZE][(INPUT_SIZE - FILTER_SIZE + 1) / POOL_SIZE]) {
    for (int i = 0; i < (INPUT_SIZE - FILTER_SIZE + 1) / POOL_SIZE; i++) {
        for (int j = 0; j < (INPUT_SIZE - FILTER_SIZE + 1) / POOL_SIZE; j++) {
            float max = input[i * POOL_SIZE][j * POOL_SIZE];
            for (int k = 0; k < POOL_SIZE; k++) {
                for (int l = 0; l < POOL_SIZE; l++) {
                    if (input[i * POOL_SIZE + k][j * POOL_SIZE + l] > max) {
                        max = input[i * POOL_SIZE + k][j * POOL_SIZE + l];
                    }
                }
            }
            output[i][j] = max;
        }
    }
}

// Function to initialize a 2D array with random values
void initialize_input(float input[INPUT_SIZE][INPUT_SIZE]) {
    for (int i = 0; i < INPUT_SIZE; i++) {
        for (int j = 0; j < INPUT_SIZE; j++) {
            input[i][j] = rand() % 100 / 10.0;
        }
    }
}

// Function to initialize a filter with random values
void initialize_filter(float filter[FILTER_SIZE][FILTER_SIZE]) {
    for (int i = 0; i < FILTER_SIZE; i++) {
        for (int j = 0; j < FILTER_SIZE; j++) {
            filter[i][j] = rand() % 10 / 10.0;
        }
    }
}
// Function that was previously main
void convolution_pooling_benchmark() {
    float input[INPUT_SIZE][INPUT_SIZE];
    float filter[FILTER_SIZE][FILTER_SIZE];
    float conv_output[INPUT_SIZE - FILTER_SIZE + 1][INPUT_SIZE - FILTER_SIZE + 1];
    float pool_output[(INPUT_SIZE - FILTER_SIZE + 1) / POOL_SIZE][(INPUT_SIZE - FILTER_SIZE + 1) / POOL_SIZE];

    printf("start cond and pool benchmark \n");

    // Initialize input and filter
    initialize_input(input);
    initialize_filter(filter);

    // Measure the convolution time
    struct timeval start, end;
    host_gettimeofday(&start, NULL);

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        conv2d(input, filter, conv_output);
    }

    host_gettimeofday(&end, NULL);
    unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));
    printf("conv2d benchmark finish time: %lf s\n",(now - then) / 1000.0);


    // Measure the pooling time
    host_gettimeofday(&start, NULL);

    for (int i = 0; i < NUM_ITERATIONS * 5; i++) {
        maxpool2d(conv_output, pool_output);
    }

    host_gettimeofday(&end, NULL);
    now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));
    printf("maxpool2d benchmark finish time: %lf s\n",(now - then) / 1000.0);

    printf("pool_output: %f\n", pool_output[0][0]);
}

/*----------------------------------------------*/


void app_main() {
    printf("start benchmark test! \n ");

    struct timeval start, end;
    host_gettimeofday(&start, NULL);

    /*--------------------------------------------*/

    //convolution_pooling_benchmark();
    //c_out_3(31, 0, 0, 0);

        dirty_page_benchmark(5000);
        c_out_3(31, 0, 0, 0);

    /*compute_flops_benchmark();
    c_out_3(31, 0, 0, 0);
    compute_iops_benchmark();
    c_out_3(31, 1, 0, 0);
    for(int i=1;i<=1024;i*=2) {
        dirty_page_benchmark(i);
        c_out_3(31, i, 0, 0);
    }
    disk_benchmark();
    c_out_3(31, 2, 0, 0);*/
    /*--------------------------------------------*/

    host_gettimeofday(&end, NULL);
    unsigned long now = (end.tv_sec * 1000ull) + (end.tv_usec / (1000ull));
    unsigned long then = (start.tv_sec * 1000ull) + (start.tv_usec / (1000ull));
    printf("benchmark finish time: %lf s\n",(now - then) / 1000.0);

    return ;
}