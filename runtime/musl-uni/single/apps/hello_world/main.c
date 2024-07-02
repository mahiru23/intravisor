/*#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>
#include <signal.h>
#include <pthread.h>


#define _GNU_SOURCE
#include <unistd.h>
*/
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>


#define MSG "hello world, just a hostcall test here \n"

#define MSGX "cons, file test success! \n"

void app_main() {
    printf("hello world here! \n ");


	char buf[32];
	char cap[16];		//place to store the capability
	long size;

	host_cap_prb("test1", cap, &size);
	//copy_from_cap(buf, cap, 32);

	//host_write_out(buf, 32);
    /*c_out_3(406, buf, cap, 32);

    c_out_3(1, buf, (long)(32), 0);*/


    //c_out_3(1, MSG, (long)sizeof(MSG), 0);
    //c_out_3(1, MSG, (long)sizeof(MSG), 0);

    int fd = host_open("testfile", 0, 0666);
    if (fd == -1) {
        printf("open error\n");
        return;
    }

    const char* str = "test write: ";

    if (host_write(fd, str, (long)strlen(str)) == -1) {
        printf("write error 1\n");
        return;
    }
    if (host_write(fd, MSG, (long)sizeof(MSG)) == -1) {
        printf("write error 2\n");
        return;
    }

    printf("write test over \n");


	int i = 0;
    while(i<17) {
		i++;
		printf(" times: %d \n ", i);
        sleep(1);
        //c_out_3(30, MSG, (long)sizeof(MSG), 0);
		if(i==10000000) {
			i=1;
		}
    }

    if (host_write(fd, MSGX, (long)sizeof(MSGX)) == -1) {
        printf("write error 3\n");
        return;
    }

    c_out_3(1, MSG, (long)sizeof(MSG), 0);
    printf("out success! \n ");
    return ;


}